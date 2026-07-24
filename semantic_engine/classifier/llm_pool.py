"""
Role-aware LLM cascade pool for Vulcan.

Three fixed roles, each with a tailored model priority list:

  detection  – fast, security-aware models; runs on EVERY finding (high volume)
               Llama-4-Scout → gpt-4.1-mini → Phi-4 → mistral-small-2503 → gpt-4.1
               → Groq Llama-3.3 → Groq Llama-4-Scout → Groq llama-3.1 → Groq gemma2-9b

  exploit    – best coders; runs ONLY on HIGH/CRITICAL confirmed vulns (low volume)
               Groq compound-beta [CRITICAL only] → DeepSeek-V3 → Llama-4-Maverick-FP8 → o4-mini → gpt-4.1
               → Groq Llama-4-Scout → Groq llama-3.3 → Groq llama-3.1 → Groq gemma2-9b
               → gpt-4.1-mini → Phi-4 → mistral-small-2503
               Groq compound-beta uses web search + code execution for richer CRITICAL PoCs (has per-call cost).

  patch      – quality-first; runs once per approved patch request
               DeepSeek-V3 → gpt-4.1 → Llama-4-Maverick-FP8 → Groq llama-3.3 → o4-mini

  report     – prose quality; runs once per ASVS compliance PDF export
               gpt-4o → gpt-4.1 → Groq llama-3.3

  All models use GitHub Models free tier (GITHUB_LLM_API_KEY) or Groq free tier (GROQ_API_KEY).
  Groq Compound (exploit/CRITICAL) is paid — billed per token + per web-search request.

Override any role's cascade via env var (semicolon-separated provider:model pairs):
  VULCAN_DETECTION_MODELS=github:gpt-4o-mini;groq:llama-3.3-70b-versatile
  VULCAN_EXPLOIT_MODELS=github:deepseek/DeepSeek-V3-0324;github:gpt-4o
  VULCAN_PATCH_MODELS=github:deepseek/DeepSeek-V3-0324;github:gpt-4o

Required env vars (set whichever providers you have):
  GITHUB_LLM_API_KEY   – GitHub Personal Access Token (free tier)
  GROQ_API_KEY         – Groq API key  (also accepted as LLM_API_KEY for patch/exploit)
  OPENAI_API_KEY       – OpenAI API key (paid, highest quality safety net)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

_GITHUB_BASE = "https://models.github.ai/inference"
_GROQ_BASE   = "https://api.groq.com/openai/v1"

# ---------------------------------------------------------------------------
# Default model cascade for each role
# key_env: environment variable that holds the API key; entry is skipped when
#          the key is absent so unconfigured providers never appear in the pool.
# ---------------------------------------------------------------------------
ROLE_DEFAULTS: dict[str, list[dict]] = {
    "detection": [
        # GitHub Models free tier — fast, structured classification
        {"provider": "github", "model": "meta/Llama-4-Scout-17B-16E-Instruct",         "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/gpt-4.1-mini",                         "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "microsoft/Phi-4",                             "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "mistral-ai/mistral-small-2503",               "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/gpt-4.1",                              "key_env": "GITHUB_LLM_API_KEY"},
        # Groq free tier — independent quota, kicks in when GitHub is exhausted/blocked
        {"provider": "groq",   "model": "llama-3.3-70b-versatile",                     "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "meta-llama/llama-4-scout-17b-16e-instruct",   "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "llama-3.1-8b-instant",                        "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "gemma2-9b-it",                                "key_env": "LLM_API_KEY"},
    ],
    "exploit": [
        # Groq Compound — web search + code execution; CRITICAL findings only (paid per-call)
        {"provider": "groq",   "model": "compound-beta",                                  "key_env": "LLM_API_KEY",        "critical_only": True},
        # Tier 1: strongest coders (GitHub free tier)
        {"provider": "github", "model": "deepseek/DeepSeek-V3-0324",                     "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "meta/Llama-4-Maverick-17B-128E-Instruct-FP8",   "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/o4-mini",                                "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/gpt-4.1",                                "key_env": "GITHUB_LLM_API_KEY"},
        # Tier 2: Groq fast inference (independent quota)
        {"provider": "groq",   "model": "meta-llama/llama-4-scout-17b-16e-instruct",     "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "llama-3.3-70b-versatile",                       "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "llama-3.1-8b-instant",                          "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "gemma2-9b-it",                                  "key_env": "LLM_API_KEY"},
        # Tier 3: GitHub last-resort fallbacks
        {"provider": "github", "model": "openai/gpt-4.1-mini",                           "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "microsoft/Phi-4",                               "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "mistral-ai/mistral-small-2503",                 "key_env": "GITHUB_LLM_API_KEY"},
    ],
    "patch": [
        # Quality-first — correctness > speed; runs once per patch request
        {"provider": "github", "model": "deepseek/DeepSeek-V3-0324",                "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/gpt-4.1",                           "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "meta/Llama-4-Maverick-17B-128E-Instruct-FP8", "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "groq",   "model": "meta-llama/llama-4-scout-17b-16e-instruct", "key_env": "LLM_API_KEY"},
        {"provider": "groq",   "model": "llama-3.3-70b-versatile",                  "key_env": "LLM_API_KEY"},
        {"provider": "github", "model": "openai/o4-mini",                           "key_env": "GITHUB_LLM_API_KEY"},
    ],
    "report": [
        # Prose quality matters more than speed here — runs once per PDF export.
        {"provider": "github", "model": "gpt-4o",                                   "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "github", "model": "openai/gpt-4.1",                           "key_env": "GITHUB_LLM_API_KEY"},
        {"provider": "groq",   "model": "llama-3.3-70b-versatile",                  "key_env": "LLM_API_KEY"},
    ],
}


class RoleAwareLLMPool:
    """
    Cascading LLM provider pool for a specific role (detection / exploit / patch).

    Behaviors
    ---------
    • Each provider:model pair has an independent exhaustion flag.
      A daily quota on gpt-4o-mini does NOT exhaust gpt-4o.
    • Per-minute rate limits get one 3 s back-off retry before skipping.
    • Daily / quota exhaustion permanently marks that model for this session.
    • Once a model succeeds it becomes "sticky" and is tried first on the
      next call, avoiding the cascade overhead on hot paths.
    """

    # Initializes provider list, exhaustion tracking, sticky model, and rate-limit state
    def __init__(
        self,
        role: str,
        timeout: int = 45,
        system_prompt: str = "",
        min_interval_ms: int = 250,
    ):
        if role not in ROLE_DEFAULTS:
            raise ValueError(f"Unknown role '{role}'. Valid: {list(ROLE_DEFAULTS)}")
        self.role            = role
        self.timeout         = timeout
        self.system_prompt   = system_prompt
        self._min_interval   = min_interval_ms / 1000.0
        self._last_call: float = 0.0
        self._rate_lock: Optional[asyncio.Lock] = None   # lazy — created in async context
        self._exhausted: set[str] = set()
        # Separate tracking: soft = scraping/rate blocks (temporary, reset between scans)
        #                     hard = daily quota (permanent for the day)
        self._soft_exhausted: set[str] = set()
        self._hard_exhausted: set[str] = set()
        self._sticky: Optional[dict] = None
        self._providers      = self._build_providers()

        active = len(self._providers)
        logger.info(f"[pool:{role}] {active} provider(s) registered")
        if active == 0:
            logger.warning(f"[pool:{role}] no API keys found — LLM disabled for this role")

    def reset_soft_exhausted(self) -> None:
        """
        Clear temporary (scraping / rate-limit) exhaustion flags so providers
        can be retried at the start of a new scan.  Daily-quota exhaustions
        (hard) are preserved — retrying those would just burn more time.
        """
        if not self._soft_exhausted:
            return
        recovered = list(self._soft_exhausted)
        self._soft_exhausted.clear()
        self._exhausted = set(self._hard_exhausted)   # rebuild from hard set only
        if self._sticky and self._sticky["id"] not in self._exhausted:
            pass  # keep sticky if it's still available
        elif self._sticky and self._sticky["id"] in self._exhausted:
            self._sticky = None
        logger.info(f"[pool:{self.role}] reset soft blocks — {len(recovered)} provider(s) available again: {recovered}")

    # ── Provider list construction ────────────────────────────────────────────

    # Builds ordered provider list from env override or role defaults, skipping missing keys
    def _build_providers(self) -> list[dict]:
        override = os.getenv(f"VULCAN_{self.role.upper()}_MODELS")
        if override:
            providers = []
            for entry in override.split(";"):
                entry = entry.strip()
                if ":" not in entry:
                    continue
                prov, model = entry.split(":", 1)
                key = self._resolve_key(prov.strip())
                if key:
                    providers.append(self._make_entry(prov.strip(), model.strip(), key))
            return providers

        providers = []
        for cfg in ROLE_DEFAULTS[self.role]:
            key = os.getenv(cfg["key_env"])
            if key:
                providers.append(self._make_entry(
                    cfg["provider"], cfg["model"], key,
                    critical_only=cfg.get("critical_only", False),
                ))
        return providers

    # Returns API key for a given provider name from environment variables
    @staticmethod
    def _resolve_key(provider: str) -> Optional[str]:
        return {
            "github": os.getenv("GITHUB_LLM_API_KEY"),
            "groq":   os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY"),
            "openai": os.getenv("OPENAI_API_KEY"),
        }.get(provider)

    # Creates a provider dict with id, model, api_key, base_url, and optional critical_only flag
    @staticmethod
    def _make_entry(provider: str, model: str, api_key: str, critical_only: bool = False) -> dict:
        base_url = (
            _GITHUB_BASE if provider == "github" else
            _GROQ_BASE   if provider == "groq"   else
            None
        )
        return {
            "id":            f"{provider}:{model}",
            "provider":      provider,
            "model":         model,
            "api_key":       api_key,
            "base_url":      base_url,
            "critical_only": critical_only,
        }

    # Creates an AsyncOpenAI client with retries disabled so the pool controls fallback
    def _make_client(self, cfg: dict):
        from openai import AsyncOpenAI
        # max_retries=0: disable SDK auto-retry so our pool controls all retry/fallback logic.
        # The SDK's built-in backoff (0.5s → 1s → 59s) hides 429 errors from us and wastes time.
        kwargs: dict = {"api_key": cfg["api_key"], "max_retries": 0}
        if cfg["base_url"]:
            kwargs["base_url"] = cfg["base_url"]
        return AsyncOpenAI(**kwargs)

    # ── Rate limiter ──────────────────────────────────────────────────────────

    # Enforces minimum interval between LLM calls using an async lock
    async def _throttle(self) -> None:
        if self._rate_lock is None:
            self._rate_lock = asyncio.Lock()
        async with self._rate_lock:
            now  = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()

    # ── Main entry point ──────────────────────────────────────────────────────

    async def call(
        self,
        messages: list,
        max_tokens: int = 1000,
        temperature: float = 0.1,
        severity: str = "",
    ) -> Optional[str]:
        """
        Call the LLM, cascading through providers until one succeeds.
        Returns response text or None when all providers are exhausted.

        severity: when provided, providers marked critical_only are skipped
                  unless severity == "critical".
        """
        if not self._providers:
            return None

        is_critical = severity.lower() == "critical"

        # Log pool state so we can diagnose why providers are skipped
        available_ids = [p["id"] for p in self._providers if p["id"] not in self._exhausted]
        skipped_ids   = [p["id"] for p in self._providers if p["id"] in self._exhausted]
        if skipped_ids:
            logger.debug(
                f"[pool:{self.role}] state: {len(available_ids)} available, "
                f"{len(skipped_ids)} exhausted — skipped: {skipped_ids}"
            )

        def _eligible(p: dict) -> bool:
            if p["id"] in self._exhausted:
                return False
            if p.get("critical_only") and not is_critical:
                return False
            return True

        # Sticky first, then the rest — all skip exhausted / non-eligible entries
        ordered: list[dict] = []
        if self._sticky and _eligible(self._sticky):
            ordered.append(self._sticky)
        for p in self._providers:
            if p is not self._sticky and _eligible(p):
                ordered.append(p)

        if not ordered:
            logger.warning(f"[pool:{self.role}] all providers exhausted")
            return None

        # Inject system prompt once if not already present
        if self.system_prompt and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": self.system_prompt}] + messages

        for cfg in ordered:
            if cfg["id"] in self._exhausted:
                continue  # exhausted by a concurrent call since ordered was built
            result = await self._try_provider(cfg, messages, max_tokens, temperature)
            if result is not None:
                self._sticky = cfg
                return result

        return None

    # Calls one provider and marks it soft-exhausted on failure; no retry on rate limits
    async def _try_provider(
        self,
        cfg: dict,
        messages: list,
        max_tokens: int,
        temperature: float,
    ) -> Optional[str]:
        pid = cfg["id"]
        try:
            await self._throttle()
            client = self._make_client(cfg)
            logger.info(f"[pool:{self.role}] → {pid}")

            response = await asyncio.wait_for(
                client.chat.completions.create(
                    model=cfg["model"],
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                ),
                timeout=self.timeout,
            )
            text = response.choices[0].message.content or ""
            logger.info(f"[pool:{self.role}] ✓ {pid} ({len(text)} chars)")
            return text

        except Exception as exc:
            msg       = str(exc).lower()
            is_daily    = any(kw in msg for kw in ("per day", "tokens per day", "daily", "tpd", "quota exceeded"))
            # "please review our" appears in GitHub's standard 429 rate-limit message —
            # that is NOT a scraping block.  Only exhaust all same-provider entries when
            # the response explicitly mentions scraping/acceptable-use.
            is_scraping = "scraping" in msg or (
                "acceptable use" in msg and "rate limit" not in msg
            )
            is_rate     = ("429" in msg or "rate limit" in msg or "too many requests" in msg or "please review our" in msg) and not is_scraping
            is_timeout  = isinstance(exc, asyncio.TimeoutError) or "timed out" in msg

            # Per-minute rate limit — soft-exhaust immediately so cascade falls to
            # next model without delay. Retrying the same model just burns 12 s and
            # hits the limit again; reset_soft_exhausted() restores it next finding.
            if is_rate and not is_daily:
                logger.warning(f"[pool:{self.role}] {pid} rate-limited — skipping to next model")
                self._exhausted.add(pid)
                self._soft_exhausted.add(pid)
                if self._sticky and self._sticky["id"] == pid:
                    self._sticky = None
                return None

            if is_scraping:
                # Temporary token-level block — exhaust ALL same-provider entries (soft)
                blocked_provider = cfg["provider"]
                for p in self._providers:
                    if p["provider"] == blocked_provider:
                        self._exhausted.add(p["id"])
                        self._soft_exhausted.add(p["id"])
                if self._sticky and self._sticky.get("provider") == blocked_provider:
                    self._sticky = None
                logger.warning(
                    f"[pool:{self.role}] {blocked_provider} token scraping-blocked "
                    f"— soft-exhausting all {blocked_provider} providers, falling to next tier"
                )
                return None

            reason = "daily quota" if is_daily else "timeout" if is_timeout else str(exc)[:100]
            logger.warning(f"[pool:{self.role}] ✗ {pid} ({reason})")
            self._exhausted.add(pid)
            if is_daily:
                self._hard_exhausted.add(pid)   # permanent for today
            else:
                self._soft_exhausted.add(pid)   # temporary — reset between scans
            if self._sticky and self._sticky["id"] == pid:
                self._sticky = None
            return None

    # ── Introspection ─────────────────────────────────────────────────────────

    # Returns True if at least one non-exhausted provider remains
    @property
    def is_available(self) -> bool:
        return any(p["id"] not in self._exhausted for p in self._providers)

    @property
    def current_model(self) -> str:
        """Return the id of the last successful provider, or 'unknown'."""
        return self._sticky["id"] if self._sticky else "unknown"

    def status(self) -> dict:
        """Return pool status — useful for /dashboard/llm-status endpoint."""
        return {
            "role": self.role,
            "available": self.is_available,
            "providers": [
                {
                    "id":        p["id"],
                    "exhausted": p["id"] in self._exhausted,
                    "sticky":    self._sticky is not None and p["id"] == self._sticky["id"],
                }
                for p in self._providers
            ],
        }

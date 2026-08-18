"""Shared confirmation toolkit (Phase 1 confirmation spine).

Every check that wants to move from a heuristic FAIL to a reproduced-impact
CONFIRMED (see verdict.py's docstring for that distinction) calls into here
instead of hand-rolling its own oracle. Centralizing this is what stops each
new check from reinventing (and subtly getting wrong) the same handful of
confirmation techniques:

  - timing_oracle: the target takes measurably longer when it actually
    executes an injected delay. The single most reusable primitive here —
    blind SQLi, blind command injection, and blind SSTI all confirm through
    it, only the payload shape differs.
  - canary()/canary_reflected_unescaped: a unique marker that's checked for
    appearing somewhere a browser would actually execute/interpret it, not
    just "present in the response" — replaces the naive `payload in
    resp.text` reflection test.
  - oob_oracle: thin wrapper over CollaboratorServer.hits_for. Already the
    pattern ssrf_probe.py hand-rolls for SSRF; generalized here so XXE,
    blind RCE, SSTI, and log4shell checks (Phase 3+) reuse one path.
  - response_diff_oracle/error_signature_oracle: moved here from checks.py
    (previously SQLi-private as _responses_differ_significantly/
    _looks_like_sql_error) — the same two heuristics are just as useful for
    boolean-blind confirmation in any other injection class.
"""
import logging
import re
import secrets
import statistics
import time
from typing import Awaitable, Callable, Tuple

from app.domain.analysis.dast.collaborator import CollaboratorServer

logger = logging.getLogger(__name__)

# Substrings of real DB error output — originally moved verbatim from
# checks.py, widened (Phase 2.1) to cover each major engine's own
# error-message vocabulary, not just the couple of strings the first pass
# happened to include. Same "well-known engine signature" idea as
# crawler.py/checks.py's other hint tuples, not an exhaustive list.
_SQL_ERROR_SIGNATURES = (
    # MySQL / MariaDB
    "sql syntax", "you have an error in your sql syntax", "mysql_fetch",
    "warning: mysqli", "mysql server version", "check the manual that corresponds "
    "to your mysql server version",
    # SQLite
    "sqlite3.operationalerror", "sqlite error", "unrecognized token",
    "sqlite_exception", "\": syntax error",
    # PostgreSQL
    "pg_query", "postgresql", "syntax error at or near", "unterminated quoted string",
    "invalid input syntax for", "npgsql.", "pg::syntaxerror", "psql:",
    # MSSQL
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft odbc", "microsoft sql server", "system.data.sqlclient",
    "incorrect syntax near", "sqlserverexception",
    # Oracle
    "ora-00933", "ora-01756", "ora-00936", "ora-00921", "ora-01789", "ora-00942",
    "pls-00103",
)

# Content-types where an HTML/JS payload structurally cannot execute no
# matter the context — a denylist, not an allowlist: many real (and
# test-fixture) responses carry a generic/missing/mislabeled content-type
# (e.g. "text/plain") for a body a browser would still render as HTML if
# reflected into a page, so the safer default for a security scanner is
# "assume dangerous unless clearly a non-renderable format", not the
# reverse — a missed reflection is worse than an extra look.
_NON_RENDERABLE_CONTENT_TYPES = ("json", "csv", "octet-stream", "pdf", "zip", "protobuf", "msgpack")

_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_EVENT_HANDLER_ATTR_RE = re.compile(r'\bon[a-zA-Z]+\s*=\s*(["\']?)(.*?)\1(?=[\s>])', re.IGNORECASE | re.DOTALL)
_ATTR_VALUE_RE = re.compile(r'=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', re.DOTALL)
# HTML-entity spellings of a quote character — an attribute value like
# id=&quot;...&quot; is properly quoted from a browser's perspective even
# though no literal '"' byte follows the '=' for _ATTR_VALUE_RE's quoted
# alternatives to match; without checking for these too, that value falls
# through to the "unquoted" branch and gets misread as dangerous.
_QUOTE_ENTITY_PREFIXES = ("&quot;", "&#34;", "&#x22;", "&#X22;", "&apos;", "&#39;", "&#x27;", "&#X27;")


async def timing_oracle(
    send_fn: Callable[[int], Awaitable[object]],
    *,
    baseline_delay: int = 0,
    injected_delay: int = 5,
    samples: int = 3,
    margin: float = 1.5,
) -> Tuple[bool, dict]:
    """Confirms a blind time-based injection by comparing an injected-delay
    payload's response time against a baseline, `samples` times each to
    smooth network jitter — a single SLEEP(5)-vs-no-SLEEP comparison is
    exactly the false-positive trap a slow/jittery network produces.

    send_fn(delay_seconds) sends one request whose payload asks the target
    to sleep/delay by delay_seconds (0 for the baseline calls,
    injected_delay for the real ones) and awaits the response. This
    function only measures wall-clock time around that call — it never
    inspects the response — so it's payload-shape-agnostic: a SQL SLEEP(),
    a shell `sleep`, a Jinja2 busy-loop all confirm through the same
    caller-supplied send_fn.

    Confirmation requires both:
      1. the baseline is stable (low variance) — a jittery/loaded target
         could otherwise make any injected delay look "confirmed" by pure
         noise alone.
      2. the injected median exceeds the baseline median by roughly
         injected_delay * margin — genuinely slower by about the amount
         requested, not just "slower than before".
    """
    baseline_ms = []
    for _ in range(samples):
        start = time.monotonic()
        await send_fn(baseline_delay)
        baseline_ms.append((time.monotonic() - start) * 1000)

    injected_ms = []
    for _ in range(samples):
        start = time.monotonic()
        await send_fn(injected_delay)
        injected_ms.append((time.monotonic() - start) * 1000)

    baseline_median = statistics.median(baseline_ms)
    injected_median = statistics.median(injected_ms)
    baseline_stdev = statistics.pstdev(baseline_ms) if len(baseline_ms) > 1 else 0.0

    injected_delay_ms = injected_delay * 1000
    # "Stable" baseline: its own jitter shouldn't itself approach the delay
    # we're about to require of the injected side.
    baseline_stable = baseline_stdev < max(500.0, injected_delay_ms * 0.25)
    delta_ms = injected_median - baseline_median
    required_delta_ms = injected_delay_ms * margin
    confirmed = bool(injected_delay) and baseline_stable and delta_ms >= required_delta_ms

    proof = {
        "baseline_ms": [round(t, 1) for t in baseline_ms],
        "injected_ms": [round(t, 1) for t in injected_ms],
        "baseline_median_ms": round(baseline_median, 1),
        "injected_median_ms": round(injected_median, 1),
        "baseline_stdev_ms": round(baseline_stdev, 1),
        "delta_ms": round(delta_ms, 1),
        "required_delta_ms": round(required_delta_ms, 1),
        "baseline_stable": baseline_stable,
    }
    return confirmed, proof


async def comparative_timing_oracle(
    send_a: Callable[[], Awaitable[object]],
    send_b: Callable[[], Awaitable[object]],
    *,
    samples: int = 7,
    noise_multiplier: float = 4.0,
    min_delta_ms: float = 5.0,
) -> Tuple[bool, dict]:
    """V11.2.5 — padding-oracle / timing-side-channel confirmation. A
    different shape from timing_oracle above: that one confirms an
    injected, KNOWN-magnitude delay (SLEEP(5) should add ~5000ms); this one
    has no known magnitude to expect at all — a padding-oracle leak is
    typically a few milliseconds of extra MAC-check/error-path work, not a
    payload-controlled delay. So instead of "does the delta match what we
    asked for", the question is "are these two DIFFERENT FIXED payloads
    (send_a = e.g. valid-padding-wrong-content ciphertext, send_b = e.g.
    invalid-padding ciphertext) distinguishable by timing at all, beyond
    what network/server jitter alone would produce."

    Interleaves A/B/A/B/... rather than sampling all of A then all of B —
    a slow drift in server load over the sampling window (a burst of other
    traffic, GC pause, autoscaling event) would otherwise bias whichever
    variant happens to run second, manufacturing a fake delta.

    Confirmation requires both:
      1. the observed median delta is at least min_delta_ms — a
         microsecond-scale difference is noise, not a usable side channel.
      2. the delta is large relative to each variant's own jitter
         (noise_multiplier * the larger of the two stdevs) — the same
         "is this really signal, not noise" bar timing_oracle applies,
         adapted for two unknown-magnitude samples instead of one known one.
    Never returns CONFIRMED-strength certainty on its own (see the caller,
    padding_oracle_probe.py, for why a distinguishable timing difference is
    reported as FAIL, not CONFIRMED) — a real exploit would still need to
    demonstrate actual plaintext recovery, which this oracle doesn't attempt.
    """
    a_ms: list = []
    b_ms: list = []
    for _ in range(samples):
        start = time.monotonic()
        await send_a()
        a_ms.append((time.monotonic() - start) * 1000)

        start = time.monotonic()
        await send_b()
        b_ms.append((time.monotonic() - start) * 1000)

    a_median = statistics.median(a_ms)
    b_median = statistics.median(b_ms)
    a_stdev = statistics.pstdev(a_ms) if len(a_ms) > 1 else 0.0
    b_stdev = statistics.pstdev(b_ms) if len(b_ms) > 1 else 0.0

    delta_ms = abs(b_median - a_median)
    noise_floor_ms = max(a_stdev, b_stdev) * noise_multiplier
    confirmed = delta_ms >= min_delta_ms and delta_ms >= noise_floor_ms

    proof = {
        "variant_a_ms": [round(t, 2) for t in a_ms],
        "variant_b_ms": [round(t, 2) for t in b_ms],
        "variant_a_median_ms": round(a_median, 2),
        "variant_b_median_ms": round(b_median, 2),
        "delta_ms": round(delta_ms, 2),
        "noise_floor_ms": round(noise_floor_ms, 2),
    }
    return confirmed, proof


def canary() -> str:
    """A unique, unguessable marker string for reflection/injection probes
    that need to grep the response for a proof-of-presence token. Fresh per
    call — unlike a fixed string, it can't collide with something already
    present in the app's own markup/content, and can't be pre-filtered by a
    WAF/cache that's seen this scanner's payloads before."""
    return f"dastcanary{secrets.token_hex(6)}"


def canary_reflected_unescaped(marker: str, body: str, content_type: str = "") -> bool:
    """True only when `marker` reflects somewhere a browser would actually
    execute/interpret it — not just "present in the response" (the naive
    `payload in resp.text` test checks.py's reflected-XSS check used to
    run, which also flags plenty of harmless reflections: inside an
    HTML-escaped attribute value, inside a plain text node, inside a JSON
    string field, ...). Deliberately regex-based, same weight class as
    crawler.py's own HTML handling — good enough to find *dangerous*
    context, not a full HTML/JS parser.

    Dangerous contexts checked:
      1. inside a <script> block — the marker becomes executable JS verbatim.
      2. inside an event-handler attribute (onclick=, onerror=, ...) — the
         marker becomes executable JS on interaction.
      3. inside an unquoted HTML attribute value — a marker containing a
         space can break out and inject a new attribute.
      4. the marker's own '<' survived HTML-encoding and opened a real tag
         — the classic '"><script>...' break-out payload shape.

    A clearly non-renderable content_type (JSON, CSV, a binary download,
    ...) is never dangerous — there's no browser HTML/JS parser downstream
    of those. Everything else (including a missing/generic/mislabeled
    content-type) is treated as potentially dangerous by default.
    """
    if content_type and any(t in content_type.lower() for t in _NON_RENDERABLE_CONTENT_TYPES):
        return False
    if not body or marker not in body:
        return False

    if any(marker in script_body for script_body in _SCRIPT_BLOCK_RE.findall(body)):
        return True

    if any(marker in handler for _quote, handler in _EVENT_HANDLER_ATTR_RE.findall(body)):
        return True

    for value_match in _ATTR_VALUE_RE.finditer(body):
        value = value_match.group(1)
        quoted = value.startswith('"') or value.startswith("'") or value.startswith(_QUOTE_ENTITY_PREFIXES)
        if marker in value and not quoted:
            return True

    # The marker itself is the tag name (e.g. an unescaped '">' breakout
    # landing a raw `<MARKERxyz onclick=...>` in the body) — the catch-all
    # below can't see this because it requires the marker to appear a
    # *second* time, after a real (non-marker) tag name; when the marker
    # forms the whole tag name there's nothing left after it to match
    # against. Checked separately, anchored right after '<'.
    if re.search(rf"<{re.escape(marker)}(?=[\s/>]|$)", body):
        return True

    # Marker reflected a second time somewhere inside a real (non-marker)
    # tag's opening — e.g. an attribute the checks above didn't already
    # flag for some other reason. Deliberately broad (matches even a
    # properly-quoted attribute value) per this module's "assume dangerous
    # unless clearly safe" bias — see the module docstring on content-type.
    if re.search(rf"<[a-zA-Z][\w:-]*[^>]*{re.escape(marker)}", body):
        return True

    return False


def oob_oracle(collaborator: CollaboratorServer, token: str) -> Tuple[bool, dict]:
    """Thin wrapper over CollaboratorServer.hits_for — the same
    out-of-band-callback pattern ssrf_probe.py already hand-rolls (see the
    end of run_ssrf_probe), pulled out here so XXE, blind RCE, SSTI, and
    log4shell checks (Phase 3+) can reuse the one path instead of
    re-implementing "did this token ever get hit"."""
    hits = collaborator.hits_for(token)
    if not hits:
        return False, {"token": token, "hits": 0}
    hit = hits[0]
    return True, {
        "token": token,
        "hits": len(hits),
        "first_hit_method": hit.method,
        "first_hit_remote_addr": hit.remote_addr,
        "first_hit_path": hit.path,
    }


def error_signature_oracle(text: str) -> bool:
    """Moved verbatim from checks.py's _looks_like_sql_error — was
    SQLi-private, but "does this response body contain a raw DB engine
    error string" is just as useful a signal for confirming any other
    injection class that can trigger a backend error (NoSQL, LDAP, XPath, ...)."""
    lowered = text.lower()
    return any(sig in lowered for sig in _SQL_ERROR_SIGNATURES)


def response_diff_oracle(a: str, b: str) -> bool:
    """Moved verbatim from checks.py's _responses_differ_significantly —
    was SQLi-private (true/false boolean-blind comparison), but the same
    heuristic applies to any boolean-blind confirmation: a real query/
    condition evaluated server-side returning a different result set for a
    true-vs-false payload usually changes response size noticeably; an app
    treating the payload as an inert string returns near-identical bodies
    either way."""
    diff = abs(len(a) - len(b))
    return diff > max(20, 0.15 * max(len(a), len(b), 1))

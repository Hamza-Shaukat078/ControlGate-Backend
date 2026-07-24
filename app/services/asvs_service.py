"""
ASVS compliance service — merges evidence from all four detection modules
(taint engine + rule catalog, config inspector, dependency scanner, dynamic
probe) plus manual attestations into one ASVSControlResult per control, and
aggregates those into the compliance summary the frontend consumes.

Verdict policy per detection_strategy:
  static_code         — a rule for this control fired: "vulnerable"-polarity
                        finding -> fail; "compliant"-polarity marker finding
                        -> pass. No finding at all: pass if every rule tagged
                        for this control is vulnerable-polarity (ran across
                        the whole repo, found nothing); not_tested if the
                        control is only covered by a weak presence marker
                        that didn't fire (regex absence isn't proof of
                        absence for those).
  config_inspection   — any "fail" finding for the control wins; else "pass"
                        if any finding at all; else not_tested (no config
                        file of the relevant type was found in the repo).
  dependency_scan     — V15.2.1 only; taken directly from the dependency
                        scanner's own SLA evaluation.
  dynamic_probe       — taken directly from the live-probe finding; not_tested
                        if no target_url was supplied for the scan.
  manual_attestation  — the human-submitted answer if one exists, else
                        not_tested.

A "fail" from any source always wins when a control has evidence from more
than one source (e.g. V3.4.1 gets both a static nginx reading and a live
HTTP header check) — conservative-by-default, consistent with how the rest
of this scanner treats overlapping evidence.
"""
import logging
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.query_store.loader import get_query_store

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether,
    )
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. ASVS PDF export will not be available.")

from semantic_engine.classifier.llm_pool import RoleAwareLLMPool

ASVS_LEVELS = ["L1", "L2", "L3"]
_LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
_VERDICT_KEYS = ["pass", "fail", "n_a", "manual_review", "not_tested"]

# Set on a finding's llm_classification.explanation when the classifier could not
# actually get an LLM opinion (rate-limited / quota-exhausted / disabled) and fell
# back to the bare static/taint match with no semantic confirmation. A "fail" built
# entirely out of these is a guess, not a verified result — see _merge_static.
_UNCONFIRMED_LLM_MARKERS = {
    "LLM unavailable — pattern-based detection only",
    "LLM cap reached — static analysis only",
}

_VERDICT_HEX = {
    "pass": "#16a34a",
    "fail": "#dc2626",
    "n_a": "#64748b",
    "manual_review": "#2563eb",
    "not_tested": "#94a3b8",
}

_report_pool: Optional["RoleAwareLLMPool"] = None


def _get_report_pool() -> "RoleAwareLLMPool":
    """Lazy singleton — GPT-4o (via the GitHub Models free tier) writes the report's
    executive summary, with automatic fallback to other models if it's unavailable."""
    global _report_pool
    if _report_pool is None:
        _report_pool = RoleAwareLLMPool(
            role="report",
            timeout=30,
            system_prompt=(
                "You are a senior application security consultant writing the executive "
                "summary of an OWASP ASVS 5.0.0 Level 1 compliance report for a client. "
                "Write 2-4 concise, professional paragraphs of plain prose — no headings, "
                "no bullet points, no markdown formatting. Summarize the overall compliance "
                "posture, call out the most significant risk areas, and give a general sense "
                "of remediation priority. Base every claim strictly on the data supplied in "
                "the user message — never invent findings, control IDs, file names, or "
                "numbers that are not present in that data."
            ),
            min_interval_ms=250,
        )
    return _report_pool


def _level_includes(control_level: str, target_level: str) -> bool:
    return _LEVEL_ORDER.get(control_level, 99) <= _LEVEL_ORDER.get(target_level, 0)


def _not_tested(control_id: str, scan_id: Optional[str]) -> dict:
    return {
        "control_id": control_id, "scan_id": scan_id, "verdict": "not_tested",
        "confidence": None, "evidence": [], "llm_explanation": None,
        "reviewed_by": None, "reviewed_at": None,
    }


class ASVSService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self._control_rule_index: Optional[dict[str, list]] = None

    # ── Catalog ───────────────────────────────────────────────────────────────

    async def list_controls(self) -> list[dict]:
        cursor = self.db.asvs_controls.find({}, {"_id": 0}).sort("control_id", 1)
        return await cursor.to_list(length=None)

    async def get_control(self, control_id: str) -> Optional[dict]:
        return await self.db.asvs_controls.find_one({"control_id": control_id}, {"_id": 0})

    async def list_chapters(self) -> list[dict]:
        controls = await self.list_controls()
        by_chapter: dict[str, list[dict]] = defaultdict(list)
        for c in controls:
            by_chapter[c["chapter_id"]].append(c)

        chapters = []
        for chapter_id, chapter_controls in sorted(by_chapter.items(), key=lambda kv: int(kv[0][1:])):
            strategies = {c["detection_strategy"] for c in chapter_controls}
            chapters.append({
                "chapter_id": chapter_id,
                "title": chapter_controls[0]["chapter"].split(": ", 1)[-1],
                "detection_strategy": next(iter(strategies)) if len(strategies) == 1 else "mixed",
                "control_count": len(chapter_controls),
            })
        return chapters

    # ── Rule-catalog index (control_id -> rules), built once and cached ──────

    def _rule_index(self) -> dict[str, list]:
        if self._control_rule_index is None:
            index: dict[str, list] = defaultdict(list)
            for rule in get_query_store().get_all_queries():
                for control_id in rule.asvs_controls:
                    index[control_id].append(rule)
            self._control_rule_index = index
        return self._control_rule_index

    # ── Per-scan result computation ──────────────────────────────────────────

    async def build_results_for_scan(self, scan_id: str) -> dict[str, dict]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        summary = (scan or {}).get("summary") or {}

        attestations = {
            a["control_id"]: a async for a in self.db.attestations.find({})
        }

        controls = await self.list_controls()
        results: dict[str, dict] = {}
        for control in controls:
            results[control["control_id"]] = self._compute_result(control, summary, attestations, scan_id)

        if results:
            for control_id, result in results.items():
                await self.db.asvs_results.update_one(
                    {"scan_id": scan_id, "control_id": control_id},
                    {"$set": result},
                    upsert=True,
                )
        return results

    def _compute_result(self, control: dict, summary: dict, attestations: dict, scan_id: str) -> dict:
        control_id = control["control_id"]
        strategy = control["detection_strategy"]

        if strategy == "manual_attestation":
            return self._merge_attestation(control_id, attestations, scan_id)
        if strategy == "static_code":
            return self._merge_static(control_id, summary, scan_id)
        if strategy == "config_inspection":
            return self._merge_config(control_id, summary, scan_id)
        if strategy == "dependency_scan":
            return self._merge_dependency(control_id, summary, scan_id)
        if strategy == "dynamic_probe":
            return self._merge_dynamic(control_id, summary, scan_id)
        return _not_tested(control_id, scan_id)

    def _merge_attestation(self, control_id: str, attestations: dict, scan_id: str) -> dict:
        att = attestations.get(control_id)
        if not att:
            return _not_tested(control_id, scan_id)
        return {
            "control_id": control_id, "scan_id": scan_id,
            "verdict": att.get("answer", "not_tested"),
            "confidence": None,
            "evidence": [{"note": att["evidence_url"]}] if att.get("evidence_url") else [],
            "llm_explanation": None,
            "reviewed_by": att.get("attested_by"),
            "reviewed_at": att.get("timestamp"),
        }

    def _merge_static(self, control_id: str, summary: dict, scan_id: str) -> dict:
        # Capability-check controls (V6.2.2/.3/.4, V6.3.1, V6.4.1, V7.2.4, V7.4.1/.2,
        # V14.3.1) have their own side-channel finding — see CapabilityChecker. It never
        # goes through the vulnerability slice/classifier pipeline (which would silently
        # discard "this isn't a vulnerability" verdicts), so check it first. Falls through
        # to the logic below, unchanged, for every other control or if it found nothing.
        for cap in summary.get("capability_findings") or []:
            if cap.get("control_id") == control_id:
                return {
                    "control_id": control_id, "scan_id": scan_id,
                    "verdict": cap.get("verdict", "not_tested"),
                    "confidence": cap.get("confidence"),
                    "evidence": [{"file": cap.get("file"), "line": cap.get("line"), "note": cap.get("note")}] if cap.get("file") else [],
                    "llm_explanation": cap.get("note"),
                    "reviewed_by": None, "reviewed_at": None,
                }

        vulns = summary.get("vulnerabilities") or []
        matches = [v for v in vulns if control_id in (v.get("asvs_controls") or [])]

        if matches:
            vulnerable_hits = [v for v in matches if v.get("asvs_finding_polarity", "vulnerable") != "compliant"]
            if vulnerable_hits:
                def _explanation(v: dict) -> str | None:
                    return (v.get("analysis", {}).get("llm_classification", {}) or {}).get("explanation")

                confirmed_hits = [v for v in vulnerable_hits if _explanation(v) not in _UNCONFIRMED_LLM_MARKERS]
                # At least one hit an LLM actually reviewed and confirmed -> a real fail.
                # If every hit is an unconfirmed static-only fallback, that's a guess the
                # tool couldn't verify, not a confident failure — surface it for a human
                # to review instead of asserting something we're not actually sure of.
                decisive_hits = confirmed_hits or vulnerable_hits
                verdict = "fail" if confirmed_hits else "manual_review"
                worst = decisive_hits[0]
                evidence = [
                    {
                        "file": v.get("location", {}).get("file"),
                        "line": v.get("location", {}).get("start_line"),
                        "note": v.get("type"),
                    }
                    for v in decisive_hits
                ]
                explanation = _explanation(worst)
                if verdict == "manual_review":
                    explanation = (
                        f"{len(vulnerable_hits)} potential finding(s) matched a static pattern, but the LLM "
                        "could not confirm them (rate-limited/unavailable during this scan). Needs human review."
                    )
                return {
                    "control_id": control_id, "scan_id": scan_id, "verdict": verdict,
                    "confidence": worst.get("confidence"), "evidence": evidence,
                    "llm_explanation": explanation, "reviewed_by": None, "reviewed_at": None,
                }
            # Only compliant-polarity (marker) findings matched -> positive evidence
            best = matches[0]
            evidence = [
                {"file": v.get("location", {}).get("file"), "line": v.get("location", {}).get("start_line"), "note": v.get("type")}
                for v in matches
            ]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
                "confidence": best.get("confidence"), "evidence": evidence,
                "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
            }

        # No findings at all — distinguish "ran and found nothing" from "only a
        # weak marker rule exists for this control and it didn't fire".
        if not summary:
            return _not_tested(control_id, scan_id)  # no scan has run yet
        rules = self._rule_index().get(control_id, [])
        # No rule covers this control at all (e.g. it's exclusively handled by
        # CapabilityChecker and found no evidence either way) — nothing actually ran,
        # so this must stay not_tested rather than falling through to an unearned pass.
        if not rules or all(r.finding_polarity == "compliant" for r in rules):
            return _not_tested(control_id, scan_id)
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
            "confidence": 0.6, "evidence": [],
            "llm_explanation": "Static analysis ran across the scanned repository and found no violation of this control.",
            "reviewed_by": None, "reviewed_at": None,
        }

    def _merge_config(self, control_id: str, summary: dict, scan_id: str) -> dict:
        findings = [f for f in (summary.get("config_findings") or []) if f.get("control_id") == control_id]
        if not findings:
            return _not_tested(control_id, scan_id)

        failing = [f for f in findings if f.get("verdict") == "fail"]
        chosen = failing or findings
        verdict = "fail" if failing else ("pass" if any(f.get("verdict") == "pass" for f in findings) else "not_tested")
        evidence = [{"file": f.get("file"), "line": f.get("line"), "note": f.get("note")} for f in chosen]
        confidence = max((f.get("confidence") or 0 for f in chosen), default=None)
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": verdict,
            "confidence": confidence, "evidence": evidence,
            "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
        }

    def _merge_dependency(self, control_id: str, summary: dict, scan_id: str) -> dict:
        if control_id != "V15.2.1":
            return _not_tested(control_id, scan_id)
        control_result = summary.get("dependency_control_result")
        if not control_result:
            return _not_tested(control_id, scan_id)

        dep_findings = summary.get("dependency_findings") or []
        evidence = [
            {"note": f"{f['package']}@{f['version']} — {f['vuln_id']} ({f['severity']})"}
            for f in dep_findings[:20]
        ]
        return {
            "control_id": control_id, "scan_id": scan_id,
            "verdict": control_result.get("verdict", "not_tested"),
            "confidence": 0.75 if dep_findings else 0.9,
            "evidence": evidence,
            "llm_explanation": control_result.get("note"),
            "reviewed_by": None, "reviewed_at": None,
        }

    def _merge_dynamic(self, control_id: str, summary: dict, scan_id: str) -> dict:
        findings = [f for f in (summary.get("dynamic_probe_findings") or []) if f.get("control_id") == control_id]
        if not findings:
            return _not_tested(control_id, scan_id)
        f = findings[0]
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": f.get("verdict", "not_tested"),
            "confidence": f.get("confidence"), "evidence": [{"note": f.get("note")}],
            "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
        }

    # ── Aggregation for the compliance summary ───────────────────────────────

    async def get_compliance_summary(self, scan_id: str) -> dict:
        results = await self.build_results_for_scan(scan_id)
        controls = await self.list_controls()

        by_chapter: dict[str, list[dict]] = defaultdict(list)
        for c in controls:
            by_chapter[c["chapter_id"]].append(c)

        chapters = []
        for chapter_id, chapter_controls in sorted(by_chapter.items(), key=lambda kv: int(kv[0][1:])):
            counts = {k: 0 for k in _VERDICT_KEYS}
            for c in chapter_controls:
                verdict = results.get(c["control_id"], {}).get("verdict", "not_tested")
                counts[verdict] = counts.get(verdict, 0) + 1
            strategies = {c["detection_strategy"] for c in chapter_controls}
            chapters.append({
                "chapter_id": chapter_id,
                "title": chapter_controls[0]["chapter"].split(": ", 1)[-1],
                "detection_strategy": next(iter(strategies)) if len(strategies) == 1 else "mixed",
                "control_count": len(chapter_controls),
                "counts": counts,
            })

        levels: dict[str, dict] = {}
        for level in ASVS_LEVELS:
            applicable = [c for c in controls if _level_includes(c["level"], level)]
            passed = [c for c in applicable if results.get(c["control_id"], {}).get("verdict") == "pass"]
            total = len(applicable)
            levels[level] = {
                "total": total, "passed": len(passed),
                "pct": round(len(passed) / total * 100) if total else 0,
            }

        return {
            "scan_id": scan_id,
            "chapters": chapters,
            "levels": levels,
            "results": results,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Portfolio dashboard (cross-repo aggregation) ─────────────────────────

    async def get_portfolio_dashboard(self, trend_length: int = 8) -> dict:
        """
        Cross-repo compliance view: for every repo with at least one completed
        scan, its latest compliance snapshot plus a short history for a trend
        line; portfolio-wide attestation coverage; and the controls failing
        across the most repos (cross-repo risk ranking). Repo names are not
        resolved here (this service only holds the Mongo handle) — the route
        layer joins them in from the SQL repositories table.
        """
        controls = await self.list_controls()
        controls_by_id = {c["control_id"]: c for c in controls}
        total_manual = sum(1 for c in controls if c["detection_strategy"] == "manual_attestation")
        answered = await self.db.attestations.count_documents({})

        cursor = self.db.scans.find(
            {"state": "COMPLETED"},
            {"scan_id": 1, "repo_id": 1, "created_at": 1, "finished_at": 1},
        ).sort("created_at", -1)
        scans = await cursor.to_list(length=None)

        by_repo: dict[Any, list[dict]] = defaultdict(list)
        for s in scans:
            by_repo[s.get("repo_id")].append(s)

        fail_counter: dict[str, int] = defaultdict(int)
        repos_out = []
        for repo_id, repo_scans in by_repo.items():
            latest = repo_scans[0]
            trend_scans = list(reversed(repo_scans[:trend_length]))

            trend = []
            latest_summary = None
            for s in trend_scans:
                s_summary = await self.get_compliance_summary(s["scan_id"])
                trend.append({
                    "scan_id": s["scan_id"],
                    "created_at": s.get("created_at"),
                    "pct": s_summary["levels"]["L1"]["pct"],
                })
                if s["scan_id"] == latest["scan_id"]:
                    latest_summary = s_summary
            if latest_summary is None:
                latest_summary = await self.get_compliance_summary(latest["scan_id"])

            l1 = latest_summary["levels"]["L1"]
            fails = [r for r in latest_summary["results"].values() if r["verdict"] == "fail"]
            not_tested = sum(1 for r in latest_summary["results"].values() if r["verdict"] == "not_tested")
            for r in fails:
                fail_counter[r["control_id"]] += 1

            repos_out.append({
                "repo_id": repo_id,
                "latest_scan_id": latest["scan_id"],
                "latest_scan_at": latest.get("created_at"),
                "scan_count": len(repo_scans),
                "l1_pct": l1["pct"],
                "passed": l1["passed"],
                "total": l1["total"],
                "fail_count": len(fails),
                "not_tested_count": not_tested,
                "trend": trend,
            })

        repos_out.sort(key=lambda r: r["l1_pct"])

        top_failing = sorted(fail_counter.items(), key=lambda kv: kv[1], reverse=True)[:5]
        top_failing_out = []
        for control_id, repo_fail_count in top_failing:
            c = controls_by_id.get(control_id, {})
            top_failing_out.append({
                "control_id": control_id,
                "description": c.get("description", ""),
                "chapter_id": c.get("chapter_id", ""),
                "level": c.get("level", ""),
                "repo_fail_count": repo_fail_count,
            })

        overall_avg_pct = round(sum(r["l1_pct"] for r in repos_out) / len(repos_out)) if repos_out else 0
        total_open_fails = sum(r["fail_count"] for r in repos_out)

        return {
            "repos": repos_out,
            "overall_avg_pct": overall_avg_pct,
            "repo_count": len(repos_out),
            "total_open_fails": total_open_fails,
            "attestation_coverage": {
                "answered": answered,
                "total": total_manual,
                "pct": round(answered / total_manual * 100) if total_manual else 0,
            },
            "top_failing_controls": top_failing_out,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Executive summary (GPT-4o via GitHub Models, with deterministic fallback) ──

    def _fallback_executive_summary(self, summary: dict, failing: list[dict], not_tested: list[dict]) -> str:
        l1 = summary["levels"].get("L1", {})
        total = l1.get("total", 0)
        worst_chapters = sorted(
            (ch for ch in summary["chapters"] if ch["counts"].get("fail", 0) > 0),
            key=lambda ch: ch["counts"]["fail"], reverse=True,
        )[:3]
        worst_text = ", ".join(f"{ch['chapter_id']} ({ch['title']})" for ch in worst_chapters) or "none"
        return (
            f"This assessment evaluated {total} OWASP ASVS 5.0.0 Level 1 requirements. "
            f"{l1.get('passed', 0)} of {total} controls ({l1.get('pct', 0)}%) currently pass "
            f"verification. {len(failing)} control(s) failed and require remediation, and "
            f"{len(not_tested)} control(s) have not yet been verified, pending a scan or manual "
            f"attestation. The chapters with the most failing controls are: {worst_text}. "
            f"Review the failing-controls section below for supporting evidence and prioritize "
            f"remediation accordingly before re-scanning to confirm closure."
        )

    async def _generate_executive_summary(self, summary: dict) -> str:
        failing = [r for r in summary["results"].values() if r["verdict"] == "fail"]
        not_tested = [r for r in summary["results"].values() if r["verdict"] == "not_tested"]
        fallback = self._fallback_executive_summary(summary, failing, not_tested)

        pool = _get_report_pool()
        if not pool.is_available:
            return fallback

        l1 = summary["levels"].get("L1", {})
        chapter_lines = "\n".join(
            f"- {ch['chapter_id']} {ch['title']}: {ch['counts'].get('pass', 0)} pass / "
            f"{ch['counts'].get('fail', 0)} fail / {ch['counts'].get('not_tested', 0)} not tested "
            f"(of {ch['control_count']} controls)"
            for ch in summary["chapters"]
        )
        fail_lines = "\n".join(
            f"- {r['control_id']}: {(r.get('llm_explanation') or (r.get('evidence') or [{}])[0].get('note') or 'failed check')}"
            for r in failing[:15]
        ) or "None"

        prompt = (
            f"Scan ID: {summary.get('scan_id')}\n"
            f"Overall Level 1 completion: {l1.get('passed', 0)}/{l1.get('total', 0)} ({l1.get('pct', 0)}%)\n\n"
            f"Chapter breakdown:\n{chapter_lines}\n\n"
            f"Failing controls ({len(failing)} total, showing up to 15):\n{fail_lines}\n\n"
            f"Not-tested controls (no automated or manual verdict yet): {len(not_tested)}\n\n"
            "Write the executive summary now."
        )

        try:
            raw = await pool.call(messages=[{"role": "user", "content": prompt}], max_tokens=500, temperature=0.3)
        except Exception:
            logger.exception("Executive summary generation failed; using deterministic fallback")
            raw = None
        return raw.strip() if raw else fallback

    @staticmethod
    def _methodology_paragraphs() -> list[str]:
        return [
            "Each of the 70 requirements is assigned one of five detection strategies, "
            "chosen for how that specific requirement can actually be verified:",
            "<b>Static code analysis</b> — an AST/CFG/DFG taint engine traces untrusted "
            "input through the codebase against a catalog of vulnerability patterns; "
            "candidate findings are then reviewed by a large language model to confirm "
            "the verdict and explain the risk in plain language.",
            "<b>Configuration inspection</b> — parses environment files, YAML, Dockerfiles, "
            "and web-server configs for the relevant security setting (cookie flags, CORS, "
            "security headers, etc.).",
            "<b>Dependency scanning</b> — cross-references the project's declared dependencies "
            "against the OSV.dev vulnerability database and evaluates them against the "
            "organization's remediation SLA.",
            "<b>Dynamic probing</b> — connects to a live target URL (when supplied) to check "
            "TLS configuration, HSTS, and public exposure of sensitive paths.",
            "<b>Manual attestation</b> — requirements that describe documentation, process, or "
            "architectural decisions cannot be verified by tooling; these are answered "
            "directly by a reviewer, with optional evidence attached.",
            "A control is marked <b>not tested</b> whenever none of the above could reach a "
            "conclusive verdict — most commonly because no scan or attestation has been "
            "submitted for it yet, not because it was checked and found acceptable. Where a "
            "control has evidence from more than one source, a failing verdict always takes "
            "precedence.",
        ]

    # ── PDF export ────────────────────────────────────────────────────────────

    async def export_pdf(self, scan_id: str, repo_name: Optional[str] = None, branch: Optional[str] = None) -> Optional[bytes]:
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not available. Install it with: pip install reportlab")
            return None

        summary = await self.get_compliance_summary(scan_id)
        controls = await self.list_controls()
        controls_by_id = {c["control_id"]: c for c in controls}
        exec_summary_text = await self._generate_executive_summary(summary)

        failing = [r for r in summary["results"].values() if r["verdict"] == "fail"]
        not_tested_count = sum(1 for r in summary["results"].values() if r["verdict"] == "not_tested")
        l1 = summary["levels"].get("L1", {})

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ASVSTitle", parent=styles["Heading1"], fontSize=24,
            textColor=colors.HexColor("#0f172a"), spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "ASVSSubtitle", parent=styles["Normal"], fontSize=12,
            textColor=colors.HexColor("#2563eb"), spaceAfter=16,
        )
        meta_style = ParagraphStyle(
            "ASVSMeta", parent=styles["Normal"], fontSize=9.5,
            textColor=colors.HexColor("#475569"), spaceAfter=3,
        )
        section_style = ParagraphStyle(
            "ASVSSection", parent=styles["Heading2"], fontSize=14,
            textColor=colors.HexColor("#0f172a"), spaceBefore=20, spaceAfter=8,
            borderColor=colors.HexColor("#2563eb"), borderWidth=0,
        )
        body_style = ParagraphStyle(
            "ASVSBody", parent=styles["Normal"], fontSize=10, leading=15,
            alignment=TA_JUSTIFY, spaceAfter=8,
        )
        cell_style = ParagraphStyle("ASVSCell", parent=styles["Normal"], fontSize=8, leading=10)

        # ── Cover / header block ──────────────────────────────────────────────
        story = [
            Paragraph("ControlGate", ParagraphStyle(
                "Brand", parent=styles["Normal"], fontSize=11,
                textColor=colors.HexColor("#2563eb"), spaceAfter=2,
            )),
            Paragraph("OWASP ASVS 5.0.0 Level 1 — Compliance Report", title_style),
            Paragraph(f"Target: {repo_name or 'Direct code scan'}" + (f"  |  Branch: {branch}" if branch else ""), subtitle_style),
            Paragraph(f"Scan ID: {scan_id}", meta_style),
            Paragraph(f"Generated: {summary['generated_at']}", meta_style),
            Spacer(1, 0.15 * inch),
        ]

        # Headline stat row
        headline_rows = [["Overall L1 Completion", "Passing", "Failing", "Not Tested"]]
        headline_rows.append([
            f"{l1.get('pct', 0)}%", str(l1.get("passed", 0)), str(len(failing)), str(not_tested_count),
        ])
        story.append(self._styled_table(headline_rows, col_widths=[140, 110, 110, 110], big=True))
        story.append(Spacer(1, 0.1 * inch))

        # ── Executive summary ─────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", section_style))
        for para in exec_summary_text.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))

        # ── Methodology ────────────────────────────────────────────────────────
        story.append(Paragraph("Methodology", section_style))
        for para in self._methodology_paragraphs():
            story.append(Paragraph(para, body_style))

        # ── Level completion ───────────────────────────────────────────────────
        story.append(Paragraph("Level Completion", section_style))
        level_rows = [["Level", "Passed", "Total", "%"]]
        for level, data in summary["levels"].items():
            level_rows.append([level, str(data["passed"]), str(data["total"]), f"{data['pct']}%"])
        story.append(self._styled_table(level_rows))

        # ── Per-chapter breakdown ──────────────────────────────────────────────
        story.append(Paragraph("Per-Chapter Breakdown", section_style))
        chapter_rows = [["Chapter", "Pass", "Fail", "N/A", "Manual Review", "Not Tested", "% Pass"]]
        for ch in summary["chapters"]:
            c = ch["counts"]
            pct = round((c.get("pass", 0) / ch["control_count"]) * 100) if ch["control_count"] else 0
            chapter_rows.append([
                f"{ch['chapter_id']}: {ch['title']}",
                str(c.get("pass", 0)), str(c.get("fail", 0)), str(c.get("n_a", 0)),
                str(c.get("manual_review", 0)), str(c.get("not_tested", 0)), f"{pct}%",
            ])
        story.append(self._styled_table(chapter_rows))

        # ── Failing controls detail ────────────────────────────────────────────
        if failing:
            story.append(PageBreak())
            story.append(Paragraph(f"Failing Controls ({len(failing)})", section_style))
            for r in sorted(failing, key=lambda r: r["control_id"]):
                control = controls_by_id.get(r["control_id"], {})
                evidence_text = "<br/>".join(
                    f"{e.get('file') or ''}:{e.get('line') or ''} — {e.get('note') or ''}".strip(" —")
                    for e in (r.get("evidence") or [])[:4]
                ) or "No inline evidence recorded."
                explanation = r.get("llm_explanation")
                block = [
                    Paragraph(
                        f"<b>{r['control_id']}</b> — {control.get('description', '')}",
                        ParagraphStyle("FailHead", parent=cell_style, fontSize=9.5, textColor=colors.HexColor("#dc2626"), spaceAfter=4),
                    ),
                    Paragraph(f"<b>Evidence:</b><br/>{evidence_text}", cell_style),
                ]
                if explanation:
                    block.append(Paragraph(f"<b>Analysis:</b> {explanation}", cell_style))
                block.append(Spacer(1, 0.12 * inch))
                story.append(KeepTogether(block))

        # ── Full control register (appendix) ───────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("Appendix: Full Control Register", section_style))
        story.append(Paragraph(
            "Every ASVS 5.0.0 Level 1 requirement and its current verdict, for full traceability.",
            body_style,
        ))
        register_rows = [["Control", "Description", "Level", "Strategy", "Verdict"]]
        for c in controls:
            r = summary["results"].get(c["control_id"], {})
            verdict = r.get("verdict", "not_tested")
            register_rows.append([
                c["control_id"],
                Paragraph(c.get("description", ""), cell_style),
                c.get("level", ""),
                c.get("detection_strategy", "").replace("_", " "),
                Paragraph(f'<font color="{_VERDICT_HEX.get(verdict, "#000000")}"><b>{verdict.replace("_", " ").upper()}</b></font>', cell_style),
            ])
        story.append(self._styled_table(register_rows, col_widths=[55, 260, 35, 75, 75], repeat_header=True))

        def _footer(canvas_obj, doc_obj):
            canvas_obj.saveState()
            canvas_obj.setFont("Helvetica", 8)
            canvas_obj.setFillColor(colors.HexColor("#94a3b8"))
            canvas_obj.drawString(0.7 * inch, 0.5 * inch, "ControlGate — OWASP ASVS 5.0.0 Level 1 Compliance Report")
            canvas_obj.drawRightString(letter[0] - 0.7 * inch, 0.5 * inch, f"Page {doc_obj.page}")
            canvas_obj.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return buffer.getvalue()

    @staticmethod
    def _styled_table(rows: list[list], col_widths: Optional[list[int]] = None, big: bool = False, repeat_header: bool = False) -> "Table":
        table = Table(rows, colWidths=col_widths, repeatRows=1 if repeat_header else 0)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 11 if big else 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6 if big else 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6 if big else 4),
        ]
        if big:
            style.append(("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"))
            style.append(("FONTSIZE", (0, 1), (-1, 1), 16))
            style.append(("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#2563eb")))
        table.setStyle(TableStyle(style))
        return table

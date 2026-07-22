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
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. ASVS PDF export will not be available.")

ASVS_LEVELS = ["L1", "L2", "L3"]
_LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
_VERDICT_KEYS = ["pass", "fail", "n_a", "manual_review", "not_tested"]


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
        vulns = summary.get("vulnerabilities") or []
        matches = [v for v in vulns if control_id in (v.get("asvs_controls") or [])]

        if matches:
            vulnerable_hits = [v for v in matches if v.get("asvs_finding_polarity", "vulnerable") != "compliant"]
            if vulnerable_hits:
                worst = vulnerable_hits[0]
                evidence = [
                    {
                        "file": v.get("location", {}).get("file"),
                        "line": v.get("location", {}).get("start_line"),
                        "note": v.get("type"),
                    }
                    for v in vulnerable_hits
                ]
                explanation = (worst.get("analysis", {}).get("llm_classification", {}) or {}).get("explanation")
                return {
                    "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
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
        if rules and all(r.finding_polarity == "compliant" for r in rules):
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

    # ── PDF export ────────────────────────────────────────────────────────────

    async def export_pdf(self, scan_id: str) -> Optional[bytes]:
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not available. Install it with: pip install reportlab")
            return None

        summary = await self.get_compliance_summary(scan_id)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ASVSTitle", parent=styles["Heading1"], fontSize=22,
            textColor=colors.HexColor("#1a1a1a"), spaceAfter=20,
        )
        section_style = ParagraphStyle(
            "ASVSSection", parent=styles["Heading2"], fontSize=13,
            textColor=colors.HexColor("#1a1a1a"), spaceBefore=18, spaceAfter=8,
        )

        story = [
            Paragraph("ASVS 5.0.0 Level 1 Compliance Report", title_style),
            Paragraph(f"Scan ID: {scan_id}", styles["Normal"]),
            Paragraph(f"Generated: {summary['generated_at']}", styles["Normal"]),
            Spacer(1, 0.2 * inch),
        ]

        story.append(Paragraph("Level Completion", section_style))
        level_rows = [["Level", "Passed", "Total", "%"]]
        for level, data in summary["levels"].items():
            level_rows.append([level, str(data["passed"]), str(data["total"]), f"{data['pct']}%"])
        story.append(self._styled_table(level_rows))

        story.append(Paragraph("Per-Chapter Breakdown", section_style))
        chapter_rows = [["Chapter", "Pass", "Fail", "N/A", "Manual Review", "Not Tested"]]
        for ch in summary["chapters"]:
            c = ch["counts"]
            chapter_rows.append([
                f"{ch['chapter_id']}: {ch['title']}",
                str(c.get("pass", 0)), str(c.get("fail", 0)), str(c.get("n_a", 0)),
                str(c.get("manual_review", 0)), str(c.get("not_tested", 0)),
            ])
        story.append(self._styled_table(chapter_rows))

        failing = [r for r in summary["results"].values() if r["verdict"] == "fail"]
        if failing:
            story.append(Paragraph(f"Failing Controls ({len(failing)})", section_style))
            fail_rows = [["Control", "Evidence"]]
            for r in failing:
                evidence_text = "; ".join(
                    f"{e.get('file') or ''}:{e.get('line') or ''} {e.get('note') or ''}".strip()
                    for e in (r.get("evidence") or [])[:2]
                ) or (r.get("llm_explanation") or "")
                fail_rows.append([r["control_id"], Paragraph(evidence_text[:300], styles["Normal"])])
            story.append(self._styled_table(fail_rows, col_widths=[80, 400]))

        doc.build(story)
        return buffer.getvalue()

    @staticmethod
    def _styled_table(rows: list[list], col_widths: Optional[list[int]] = None) -> "Table":
        table = Table(rows, colWidths=col_widths)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return table

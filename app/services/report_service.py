from typing import Optional
from io import BytesIO, StringIO
import logging
import csv
from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan import ScanSummary
from app.db.mongo import to_object_id
from app.enums.role import UserRole
logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. PDF generation will not be available.")


class ReportService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    def _base_filter(self, user: dict) -> dict:
        if user.get("role") == UserRole.ADMIN.value:
            return {"state": "COMPLETED"}
        object_id = to_object_id(user.get("id", ""))
        if not object_id:
            return {"state": "COMPLETED", "user_id": None}
        return {"state": "COMPLETED", "user_id": {"$in": [object_id, str(user.get("id"))]}}

    async def _get_summary(self, scan_id: str, user: dict) -> Optional[ScanSummary]:
        query = {"scan_id": scan_id, **self._base_filter(user)}
        scan = await self.db.scans.find_one(query)
        if not scan or not scan.get("summary"):
            return None
        summary = scan["summary"]
        merged = {
            "scan_id": scan_id,
            "user_id": str(scan.get("user_id")),
            "status": summary.get("status", scan.get("state", "UNKNOWN")),
            "input_type": summary.get("input_type", scan.get("input_type")),
            "total_files": summary.get("total_files", scan.get("total_files", 0)),
            "files_scanned": summary.get("files_scanned", scan.get("files_scanned", 0)),
            "vulnerabilities_found": summary.get(
                "vulnerabilities_found",
                len(summary.get("vulnerabilities", []) or []),
            ),
            "by_severity": summary.get("by_severity", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            "duration_seconds": summary.get("duration_seconds", 0.0),
            "created_at": summary.get("created_at", scan.get("created_at")),
            "completed_at": summary.get("completed_at", scan.get("finished_at")),
            "vulnerabilities": summary.get("vulnerabilities"),
            "scanned_files": summary.get("scanned_files"),
            "config_findings": summary.get("config_findings"),
            "dependency_findings": summary.get("dependency_findings"),
            "dependency_control_result": summary.get("dependency_control_result"),
            "capability_findings": summary.get("capability_findings"),
            "dynamic_probe_findings": summary.get("dynamic_probe_findings"),
            "dynamic_findings": summary.get("dynamic_findings"),
            "discovered_forms": summary.get("discovered_forms"),
        }
        return ScanSummary(**merged)

    async def list(
        self,
        user: dict,
        repo_id: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        tag: str | None = None,
    ):
        """List all reports/scans"""
        reports = []
        query = self._base_filter(user)
        cursor = self.db.scans.find(query)
        async for scan in cursor:
            summary = scan.get("summary") or {}
            by_severity = summary.get("by_severity", {})
            reports.append(
                {
                    "id": scan.get("scan_id"),
                    "scan_id": scan.get("scan_id"),
                    "created_at": summary.get("created_at"),
                    "completed_at": summary.get("completed_at"),
                    "total_vulns": summary.get("vulnerabilities_found", 0),
                    "critical": by_severity.get("critical", 0),
                    "high": by_severity.get("high", 0),
                    "medium": by_severity.get("medium", 0),
                    "low": by_severity.get("low", 0),
                    "input_type": summary.get("input_type"),
                }
            )
        return reports

    async def get(self, scan_id: str, user: dict):
        """Get a specific report by scan_id"""
        summary = await self._get_summary(scan_id, user)
        if not summary:
            return None
        vulnerabilities = summary.vulnerabilities or []
        return {
            "id": scan_id,
            "scan_id": scan_id,
            "summary": {
                "total_vulns": summary.vulnerabilities_found,
                "critical": summary.by_severity.get("critical", 0),
                "high": summary.by_severity.get("high", 0),
                "medium": summary.by_severity.get("medium", 0),
                "low": summary.by_severity.get("low", 0),
            },
            "vulnerabilities": vulnerabilities,
            "config_findings": summary.config_findings or [],
            "dependency_findings": summary.dependency_findings or [],
            "capability_findings": summary.capability_findings or [],
            "dynamic_probe_findings": summary.dynamic_probe_findings or [],
            "dynamic_findings": summary.dynamic_findings or [],
            "discovered_forms": summary.discovered_forms or [],
            "created_at": summary.created_at,
            "completed_at": summary.completed_at,
            "duration_seconds": summary.duration_seconds,
        }

    @staticmethod
    def _xe(text) -> str:
        """Escape XML special chars for use inside Paragraph markup."""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    @staticmethod
    def _confirmation_label(vuln: dict) -> str:
        """Distinguishes the dynamic-confirmation tiers scan_service.py sets
        on a static finding (see _run_repository_scan's hybrid block):
        bridge_confirmed is precise (this exact route was re-tested live via
        app/domain/analysis/dast/bridge.py), plain dynamic_confirmed is only
        coarse correlation (some dynamic finding happened to share the same
        ASVS control). Reporting them identically would overstate the
        coarse tier's confidence. Within bridge_confirmed, bridge_verdict
        further distinguishes CONFIRMED (impact actually reproduced — timing
        delay measured, OOB callback received, etc.) from a plain FAIL
        (heuristic signal only, e.g. a response diff)."""
        if vuln.get('bridge_confirmed'):
            if vuln.get('bridge_verdict') == 'confirmed':
                return "CONFIRMED live — this exact route was re-tested and impact was reproduced"
            return "Confirmed live — this exact route was re-tested and reproduced"
        if vuln.get('dynamic_contradicted'):
            # Phase 5.2 — reverse bridge: the same route re-tested clean.
            # Distinct from (and checked ahead of) the coarse dynamic_confirmed
            # branch below — a precise same-route PASS is more informative
            # than a coarse cross-route correlation even though it points the
            # opposite direction, and scan_service.py never sets both
            # bridge_confirmed and dynamic_contradicted on the same finding.
            return (
                "Live-tested, not reproduced — this exact route was re-tested and passed; confidence "
                "lowered (may be a false positive, or the check simply couldn't trigger it)"
            )
        if vuln.get('dynamic_confirmed'):
            return "Corroborated — the dynamic scan flagged the same ASVS control elsewhere"
        return ""

    @staticmethod
    def _bridge_origin_label(finding: dict) -> str:
        """A bridge-originated dynamic finding's evidence is tagged
        'bridge:<static_finding_id>:<source_file>:<source_line>' by
        scan_service._run_dynamic_checks — surface the file:line it re-tested."""
        evidence = finding.get('evidence') or ''
        if not evidence.startswith('bridge:'):
            return ""
        parts = evidence.split(':', 3)
        if len(parts) < 4:
            return ""
        return f"Re-test of the static finding at {parts[2]}:{parts[3]}"

    async def export_pdf(self, scan_id: str, user: dict) -> Optional[bytes]:
        """Generate PDF report for a scan"""
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not available. Install it with: pip install reportlab")
            return None

        summary = await self._get_summary(scan_id, user)
        if not summary:
            return None

        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
            )

            sub_heading_style = ParagraphStyle(
                'SubHeading',
                parent=styles['Normal'],
                fontSize=11,
                textColor=colors.HexColor('#333333'),
                spaceAfter=6,
                spaceBefore=6,
                fontName='Helvetica-Bold',
            )

            # Add Heading4 style if not exists
            if 'Heading4' not in styles:
                styles.add(ParagraphStyle(
                    name='Heading4',
                    parent=styles['Heading3'],
                    fontSize=11,
                    textColor=colors.HexColor('#333333'),
                    spaceAfter=6,
                    spaceBefore=6,
                ))

            # Title
            story.append(Paragraph("Vulnerability Scan Report", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Scan Info
            info_data = [
                ['Scan ID:', scan_id],
                ['Status:', str(summary.status or 'N/A')],
                ['Input Type:', str(summary.input_type or 'N/A')],
                ['Files Scanned:', f"{summary.files_scanned} / {summary.total_files}"],
                ['Duration:', f"{summary.duration_seconds}s"],
                ['Created:', str(summary.created_at or 'N/A')],
                ['Completed:', str(summary.completed_at or 'N/A')],
            ]

            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 0.3 * inch))

            # Severity Summary
            story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
            story.append(Spacer(1, 0.1 * inch))

            severity_data = [
                ['Severity', 'Count'],
                ['Critical', str(summary.by_severity.get('critical', 0))],
                ['High', str(summary.by_severity.get('high', 0))],
                ['Medium', str(summary.by_severity.get('medium', 0))],
                ['Low', str(summary.by_severity.get('low', 0))],
                ['Total', str(summary.vulnerabilities_found)],
            ]

            severity_table = Table(severity_data, colWidths=[3*inch, 2*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, -1), (-1, -1), colors.beige),
            ]))
            story.append(severity_table)
            story.append(Spacer(1, 0.3 * inch))

            # ASVS Compliance by Level — the PDF had no compliance-level
            # content at all before this (only vulnerability/dependency/
            # dynamic-finding sections); asvs_service.py already computes
            # all three ASVS levels (ASVS_LEVELS = ["L1", "L2", "L3"]) for
            # the on-screen report, so this reuses the exact same call
            # rather than recomputing anything. L2/L3 totals are always >=
            # L1's (each level is a strict superset of the one below —
            # _level_includes) and their pct is typically lower — expected,
            # not a bug: more controls apply, not fewer of the same ones
            # passing.
            try:
                from app.services.asvs_service import ASVSService
                compliance = await ASVSService(self.db).get_compliance_summary(scan_id, user=user)
            except Exception as exc:
                logger.warning(f"Compliance summary unavailable for PDF (non-blocking): {exc}")
                compliance = None

            if compliance and compliance.get("levels"):
                story.append(Paragraph("ASVS Compliance by Level", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                level_labels = {"L1": "Level 1 (Opportunistic)", "L2": "Level 2 (Standard)", "L3": "Level 3 (Advanced)"}
                # Overall first — every control in the catalog counted once,
                # no level filtering (see asvs_service.py's "overall" entry).
                # The single headline number; L1/L2/L3 below are the breakdown.
                overall = compliance["levels"].get("overall", {})
                level_data = [
                    ['Level', 'Compliance', 'Controls Passing'],
                    ['Overall (out of 100)', f"{overall.get('pct', 0)} / 100", f"{overall.get('passed', 0)} / {overall.get('total', 0)}"],
                ]
                for level_id in ("L1", "L2", "L3"):
                    lvl = compliance["levels"].get(level_id, {})
                    level_data.append([
                        level_labels.get(level_id, level_id),
                        f"{lvl.get('pct', 0)}%",
                        f"{lvl.get('passed', 0)} / {lvl.get('total', 0)}",
                    ])

                level_table = Table(level_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
                level_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 1), (-1, 1), colors.beige),
                ]))
                story.append(level_table)
                story.append(Paragraph(
                    "<i>Each level is a superset of the one below it — a lower L3 percentage than L1 means "
                    "more controls apply, not that fewer of the same ones are passing.</i>",
                    styles['Normal'],
                ))
                story.append(Spacer(1, 0.3 * inch))

            # Live Confirmation Summary — only meaningful for hybrid scans
            # (dynamic_findings present); tells the reader up front how many
            # static findings were actually re-tested live vs. only
            # correlated by shared ASVS control, before they read the detail
            # sections below.
            if summary.vulnerabilities:
                bridge_confirmed_count = sum(
                    1 for v in summary.vulnerabilities if v.get('bridge_confirmed')
                )
                coarse_confirmed_count = sum(
                    1 for v in summary.vulnerabilities
                    if v.get('dynamic_confirmed') and not v.get('bridge_confirmed')
                )
                # Phase 5.2 — reverse bridge: a distinct, de-emphasized tier.
                # Counted separately from (and never overlapping with) the
                # two positive-confirmation tiers above — scan_service.py
                # never sets dynamic_contradicted on a bridge_confirmed
                # finding — so this line reads as "here's what live-tested
                # clean" rather than competing with "here's what's confirmed".
                contradicted_count = sum(
                    1 for v in summary.vulnerabilities if v.get('dynamic_contradicted')
                )
                if bridge_confirmed_count or coarse_confirmed_count or contradicted_count:
                    story.append(Paragraph("Live Confirmation Summary", styles['Heading2']))
                    story.append(Spacer(1, 0.1 * inch))
                    confirm_text = ""
                    if bridge_confirmed_count:
                        confirm_text += (
                            f"<b>{bridge_confirmed_count}</b> finding(s) confirmed live "
                            f"— exact route re-tested and reproduced<br/>"
                        )
                    if coarse_confirmed_count:
                        confirm_text += (
                            f"<b>{coarse_confirmed_count}</b> finding(s) corroborated "
                            f"— dynamic scan flagged the same ASVS control elsewhere<br/>"
                        )
                    if contradicted_count:
                        confirm_text += (
                            f"<i>{contradicted_count} finding(s) live-tested, not reproduced — exact route "
                            f"re-tested and passed; confidence lowered, not dropped</i><br/>"
                        )
                    story.append(Paragraph(confirm_text, styles['Normal']))
                    story.append(Spacer(1, 0.2 * inch))

            # Vulnerabilities Details
            if summary.vulnerabilities:
                story.append(Paragraph("Vulnerability Details", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                xe = self._xe  # shorthand

                for idx, vuln in enumerate(summary.vulnerabilities, 1):
                    # Title with severity
                    vuln_type = xe(vuln.get('type', 'Unknown Vulnerability'))
                    severity = xe(vuln.get('severity', 'unknown').upper())
                    score_label = f" — Est. CVSS {vuln.get('cvss_score')}" if isinstance(vuln.get('cvss_score'), (int, float)) else ""
                    vuln_title = f"{idx}. {vuln_type} - {severity}{xe(score_label)}"
                    story.append(Paragraph(vuln_title, styles['Heading3']))

                    # Basic info
                    location = vuln.get('location', {}) or {}
                    file_path = xe(location.get('file', 'N/A'))
                    start_line = xe(location.get('start_line', 'N/A'))
                    end_line = xe(location.get('end_line', 'N/A'))
                    confidence_val = vuln.get('confidence', 0) or 0
                    try:
                        confidence_pct = f"{float(confidence_val) * 100:.0f}%"
                    except (TypeError, ValueError):
                        confidence_pct = str(confidence_val)

                    info_text = f"<b>Location:</b> {file_path} (Lines {start_line}-{end_line})<br/>"
                    info_text += f"<b>CWE:</b> {xe(vuln.get('cwe', 'N/A'))}<br/>"
                    info_text += f"<b>OWASP:</b> {xe(vuln.get('owasp', 'N/A'))}<br/>"
                    # "Est." because this is pipeline.py's severity+exploitability
                    # heuristic (_compute_cvss_score), not an NVD lookup — a static
                    # finding has no CVE to look up. Labeled distinctly from the
                    # dependency section's real NVD CVSS below so neither reads as
                    # more/less authoritative than it actually is.
                    if isinstance(vuln.get('cvss_score'), (int, float)):
                        info_text += f"<b>Est. CVSS:</b> {vuln.get('cvss_score')}<br/>"
                    info_text += f"<b>Confidence:</b> {confidence_pct}<br/>"
                    confirmation = self._confirmation_label(vuln)
                    if confirmation:
                        info_text += f"<b>Dynamic Confirmation:</b> {xe(confirmation)}<br/>"
                    story.append(Paragraph(info_text, styles['Normal']))
                    story.append(Spacer(1, 0.1 * inch))

                    # Data Flow Analysis
                    evidence = vuln.get('evidence', {}) or {}
                    if evidence:
                        story.append(Paragraph("<b>Data Flow Analysis</b>", sub_heading_style))
                        flow_text = f"<b>Source:</b> {xe(evidence.get('source', 'N/A'))}<br/>"
                        flow_text += f"<b>Sink:</b> {xe(evidence.get('sink', 'N/A'))}<br/>"
                        flow_text += f"<b>Pattern:</b> {xe(evidence.get('pattern', 'N/A'))}<br/>"
                        story.append(Paragraph(flow_text, styles['Normal']))
                        story.append(Spacer(1, 0.1 * inch))

                    # Static Detection
                    analysis = vuln.get('analysis', {}) or {}
                    static_detection = analysis.get('static_detection', {}) or {}
                    if static_detection and static_detection.get('reason'):
                        story.append(Paragraph("<b>Static Detection</b>", sub_heading_style))
                        detection_text = xe(static_detection.get('reason', 'No details available'))
                        story.append(Paragraph(detection_text, styles['Normal']))
                        story.append(Spacer(1, 0.1 * inch))

                    # Code Snippet
                    code_snippet = evidence.get('code_snippet')
                    if code_snippet:
                        story.append(Paragraph("<b>Vulnerable Code</b>", sub_heading_style))

                        code_style = ParagraphStyle(
                            f'CodeBlock_{idx}',
                            parent=styles['Code'],
                            fontSize=8,
                            fontName='Courier',
                            leftIndent=20,
                            rightIndent=20,
                            backColor=colors.HexColor('#f5f5f5'),
                            borderPadding=10,
                            leading=12,
                            spaceBefore=6,
                            spaceAfter=6,
                        )

                        # Preformatted doesn't parse XML — safe for raw code
                        # Truncate very long snippets to avoid layout issues
                        snippet_text = code_snippet[:2000] if len(code_snippet) > 2000 else code_snippet
                        story.append(Preformatted(snippet_text, code_style))
                        story.append(Spacer(1, 0.1 * inch))

                    # AI Analysis
                    llm_classification = analysis.get('llm_classification', {}) or {}
                    if llm_classification:
                        story.append(Paragraph("<b>AI Analysis</b>", sub_heading_style))

                        explanation = llm_classification.get('explanation', '')
                        if explanation:
                            story.append(Paragraph(f"<b>Analysis:</b> {xe(explanation)}", styles['Normal']))
                            story.append(Spacer(1, 0.05 * inch))

                        remediation = llm_classification.get('remediation', '')
                        if remediation:
                            story.append(Paragraph("<b>Recommended Fix</b>", sub_heading_style))
                            story.append(Paragraph(xe(remediation), styles['Normal']))

                        exploitability = llm_classification.get('exploitability', 0)
                        if exploitability:
                            try:
                                expl_pct = f"{float(exploitability) * 100:.0f}%"
                            except (TypeError, ValueError):
                                expl_pct = str(exploitability)
                            story.append(Paragraph(f"<b>Exploitability:</b> {expl_pct}", styles['Normal']))

                    story.append(Spacer(1, 0.3 * inch))

            # Known-vulnerable dependencies (V15.2.1) — CVE / CVSS reporting.
            # OSV.dev finds *which* CVE applies to a dependency; NVD enrichment
            # (dependency_scanner.py::enrich_with_nvd) attaches the authoritative
            # CVSS score where it was reached within that scan's rate-limit
            # budget. Sorted worst-first (highest CVSS, then SLA-breached) since
            # that's what a reader wants at the top, not scan/discovery order.
            if summary.dependency_findings:
                story.append(Paragraph("Known-Vulnerable Dependencies (CVE)", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                xe = self._xe

                def _sort_key(dep: dict) -> tuple:
                    best_score = max(
                        (cd.get('cvss_score') or 0 for cd in (dep.get('cve_details') or [])),
                        default=0,
                    )
                    return (-best_score, not dep.get('breached_sla', False))

                for idx, dep in enumerate(sorted(summary.dependency_findings, key=_sort_key), 1):
                    cve_details = dep.get('cve_details') or []
                    best_cvss = max((cd.get('cvss_score') or 0 for cd in cve_details), default=None)
                    cve_ids = dep.get('cve_ids') or ([dep.get('vuln_id')] if dep.get('vuln_id') else [])
                    label = f"{dep.get('package', 'unknown')}@{dep.get('version', '?')}"
                    score_label = f" — CVSS {best_cvss}" if best_cvss else ""
                    dep_title = f"{idx}. {label} ({', '.join(xe(c) for c in cve_ids) or xe(dep.get('vuln_id', 'N/A'))}){xe(score_label)}"
                    story.append(Paragraph(dep_title, styles['Heading3']))

                    info_text = f"<b>Severity:</b> {xe(dep.get('severity', 'N/A'))}<br/>"
                    info_text += f"<b>Ecosystem:</b> {xe(dep.get('ecosystem', 'N/A'))}<br/>"
                    if dep.get('breached_sla'):
                        info_text += (
                            f"<b>Remediation SLA:</b> BREACHED "
                            f"({xe(dep.get('days_since_published'))}d since publish, "
                            f"SLA {xe(dep.get('sla_days'))}d)<br/>"
                        )
                    description = None
                    if cve_details:
                        description = cve_details[0].get('description')
                    info_text += f"<b>Summary:</b> {xe(description or dep.get('summary', 'N/A'))}<br/>"
                    story.append(Paragraph(info_text, styles['Normal']))

                    for cd in cve_details:
                        if cd.get('references'):
                            refs = ", ".join(cd['references'][:3])
                            story.append(Paragraph(f"<b>References:</b> {xe(refs)}", styles['Normal']))

                    if not cve_details and cve_ids:
                        story.append(Paragraph(
                            "<i>CVSS score not available — NVD enrichment did not reach this CVE "
                            "within this scan's lookup budget.</i>", styles['Normal'],
                        ))

                    story.append(Spacer(1, 0.2 * inch))

            # Dynamic (DAST) Findings
            if summary.dynamic_findings:
                story.append(Paragraph("Dynamic Scan Findings", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                xe = self._xe
                for idx, finding in enumerate(summary.dynamic_findings, 1):
                    verdict = xe(str(finding.get('verdict', 'unknown')).upper())
                    rule_id = xe(finding.get('rule_id', 'Unknown'))
                    control_id = xe(finding.get('control_id', 'N/A'))
                    finding_title = f"{idx}. {rule_id} ({control_id}) - {verdict}"
                    story.append(Paragraph(finding_title, styles['Heading3']))

                    info_text = f"<b>URL:</b> {xe(finding.get('url', 'N/A'))}<br/>"
                    info_text += f"<b>Method:</b> {xe(finding.get('method', 'N/A'))}<br/>"
                    info_text += f"<b>Note:</b> {xe(finding.get('note', 'N/A'))}<br/>"
                    bridge_origin = self._bridge_origin_label(finding)
                    if bridge_origin:
                        info_text += f"<b>Origin:</b> {xe(bridge_origin)}<br/>"
                    elif finding.get('corroborates_static_finding'):
                        info_text += (
                            "<b>Corroborates:</b> A static finding flagged the same ASVS control<br/>"
                        )
                    # CONFIRMED means the engine reproduced impact, not just a
                    # heuristic signal — the reproduction string is the
                    # human-pasteable receipt for that, so it's worth
                    # surfacing even when evidence/proof are omitted for size.
                    if finding.get('verdict') == 'confirmed':
                        info_text += "<b>Impact reproduced:</b> yes<br/>"
                    # payload is the actual attack value sent (e.g. the SSRF
                    # callback URL, the SQLi boolean pair). Every check now
                    # populates payload/proof on every verdict it reaches
                    # (pass included — a PASS is a real tested result, not
                    # just a claim), not only confirmed/fail, so this no
                    # longer gates on verdict — whatever the check actually
                    # captured is shown, whichever way it came out.
                    if finding.get('payload'):
                        info_text += f"<b>Payload:</b> {xe(finding.get('payload'))}<br/>"
                    # proof is check-specific structured evidence (see
                    # DynamicFinding's docstring) — a real response snippet
                    # for a response-diff check, an out-of-band callback's
                    # source IP for SSRF, timing deltas for blind SQLi.
                    # Rendered generically (whatever keys are present)
                    # rather than one hand-coded layout per rule_id.
                    proof = finding.get('proof')
                    if proof:
                        for key, value in proof.items():
                            if value in (None, ""):
                                continue
                            label = xe(str(key).replace('_', ' ').title())
                            info_text += f"<b>{label}:</b> {xe(str(value))}<br/>"
                    if finding.get('reproduction'):
                        info_text += f"<b>Reproduction:</b> {xe(finding.get('reproduction'))}<br/>"
                    story.append(Paragraph(info_text, styles['Normal']))
                    story.append(Spacer(1, 0.2 * inch))

            # Live ASVS Dynamic-Probe Checks — DynamicProbe's TLS/HTTPS/cert/
            # HSTS/.git-exposure results (the catalog's dynamic_probe-labeled
            # controls, plus the V3.4.1/V13.4.6 config-inspection controls
            # that accept this as alternate evidence). Distinct from the
            # section above: these are direct live-property checks, not
            # payload/injection probes, and they feed ASVS verdicts directly
            # rather than only corroborating a static finding.
            if summary.dynamic_probe_findings:
                story.append(Paragraph("Live ASVS Dynamic-Probe Checks", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                xe = self._xe
                for idx, finding in enumerate(summary.dynamic_probe_findings, 1):
                    verdict = xe(str(finding.get('verdict', 'unknown')).upper())
                    control_id = xe(finding.get('control_id', 'N/A'))
                    finding_title = f"{idx}. {control_id} - {verdict}"
                    story.append(Paragraph(finding_title, styles['Heading3']))

                    info_text = f"<b>Note:</b> {xe(finding.get('note', 'N/A'))}<br/>"
                    if finding.get('confidence') is not None:
                        info_text += f"<b>Confidence:</b> {xe(finding.get('confidence'))}<br/>"
                    story.append(Paragraph(info_text, styles['Normal']))
                    story.append(Spacer(1, 0.2 * inch))

            # Discovered forms are informational only (never auto-submitted) —
            # surfaced so a reader knows what the crawler found, not a finding.
            if summary.discovered_forms:
                story.append(Paragraph("Discovered Forms (not submitted)", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))
                for form in summary.discovered_forms:
                    xe = self._xe
                    form_text = f"<b>{xe(form.get('method', 'GET'))}</b> {xe(form.get('action_url', 'N/A'))} " \
                                f"— fields: {xe(', '.join(form.get('fields', []) or []))}"
                    story.append(Paragraph(form_text, styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))

            # Build PDF
            doc.build(story)
            buffer.seek(0)
            return buffer.getvalue()

        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}", exc_info=True)
            return None

    async def export_csv(self, scan_id: str, user: dict) -> Optional[str]:
        """Generate CSV export for a scan"""
        summary = await self._get_summary(scan_id, user)
        if not summary or not (summary.vulnerabilities or summary.dynamic_findings):
            return None

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(['Type', 'Severity', 'File', 'Line', 'Message', 'CWE', 'Confirmation', 'Reproduction'])

        # Vulnerabilities
        for vuln in summary.vulnerabilities or []:
            writer.writerow([
                vuln.get('type', 'Unknown'),
                vuln.get('severity', 'UNKNOWN'),
                vuln.get('file', 'N/A'),
                vuln.get('line', 'N/A'),
                vuln.get('message', 'No description'),
                vuln.get('cwe', ''),
                self._confirmation_label(vuln),
                '',
            ])

        # Dynamic (DAST) findings — HTTP-shaped, not file/line-shaped, so
        # File/Line hold the URL and verdict respectively for this row type.
        for finding in summary.dynamic_findings or []:
            bridge_origin = self._bridge_origin_label(finding)
            confirmation = (
                bridge_origin if bridge_origin
                else "Corroborates static finding" if finding.get('corroborates_static_finding')
                else ""
            )
            writer.writerow([
                finding.get('rule_id', 'Unknown'),
                finding.get('verdict', 'unknown').upper(),
                finding.get('url', 'N/A'),
                finding.get('method', 'N/A'),
                finding.get('note', 'No description'),
                '',
                confirmation,
                finding.get('reproduction') or '',
            ])

        return output.getvalue()

    async def export(self, scan_id: str, fmt: str, user: dict):
        """Export report in specified format"""
        if fmt == "json":
            return await self.get(scan_id, user)
        elif fmt == "csv":
            csv_content = await self.export_csv(scan_id, user)
            if csv_content:
                return {"content": csv_content}
            return {"detail": "No data available for CSV export"}
        elif fmt == "pdf":
            # This shouldn't be called directly - use export_pdf for binary response
            return {"detail": "Use /export endpoint with Accept: application/pdf header"}
        return {"detail": "Unsupported format"}

    async def compare(self, scan_id_1: str, scan_id_2: str, user: dict):
        """Compare two scan reports"""
        report1 = await self.get(scan_id_1, user)
        report2 = await self.get(scan_id_2, user)
        
        if not report1 or not report2:
            return {"detail": "One or both scans not found"}
        
        return {
            "report_1": report1["summary"],
            "report_2": report2["summary"],
            "diff": {
                "total_vulns_diff": report2["summary"]["total_vulns"] - report1["summary"]["total_vulns"],
                "critical_diff": report2["summary"]["critical"] - report1["summary"]["critical"],
                "high_diff": report2["summary"]["high"] - report1["summary"]["high"],
                "medium_diff": report2["summary"]["medium"] - report1["summary"]["medium"],
                "low_diff": report2["summary"]["low"] - report1["summary"]["low"],
            },
        }

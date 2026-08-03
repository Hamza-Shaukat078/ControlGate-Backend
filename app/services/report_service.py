from typing import Optional
from io import BytesIO
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
            "created_at": summary.created_at,
            "completed_at": summary.completed_at,
            "duration_seconds": summary.duration_seconds,
        }

    @staticmethod
    def _xe(text) -> str:
        """Escape XML special chars for use inside Paragraph markup."""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

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

            # Vulnerabilities Details
            if summary.vulnerabilities:
                story.append(Paragraph("Vulnerability Details", styles['Heading2']))
                story.append(Spacer(1, 0.1 * inch))

                xe = self._xe  # shorthand

                for idx, vuln in enumerate(summary.vulnerabilities, 1):
                    # Title with severity
                    vuln_type = xe(vuln.get('type', 'Unknown Vulnerability'))
                    severity = xe(vuln.get('severity', 'unknown').upper())
                    vuln_title = f"{idx}. {vuln_type} - {severity}"
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
                    info_text += f"<b>Confidence:</b> {confidence_pct}<br/>"
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
        if not summary or not summary.vulnerabilities:
            return None
        
        output = BytesIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Type', 'Severity', 'File', 'Line', 'Message', 'CWE'])
        
        # Vulnerabilities
        for vuln in summary.vulnerabilities:
            writer.writerow([
                vuln.get('type', 'Unknown'),
                vuln.get('severity', 'UNKNOWN'),
                vuln.get('file', 'N/A'),
                vuln.get('line', 'N/A'),
                vuln.get('message', 'No description'),
                vuln.get('cwe', '')
            ])
        
        output.seek(0)
        return output.getvalue().decode('utf-8')

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

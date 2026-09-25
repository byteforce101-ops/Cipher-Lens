"""
PDF report generation module using Jinja2 and WeasyPrint.
Renders an executive security assessment report with remediation diffs and compliance badges.
Outputs to backend/reports_storage/.
"""

import os
from typing import Any, Dict
from jinja2 import Template

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports_storage"))
os.makedirs(REPORTS_DIR, exist_ok=True)

REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IPsec Security Assessment - {{ scan_name }}</title>
<style>
  @page {
    size: A4;
    margin: 18mm 16mm;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1a1a1a;
    line-height: 1.45;
    font-size: 10pt;
  }
  .header {
    border-bottom: 2px solid #c88750;
    padding-bottom: 10px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }
  .header h1 {
    font-size: 22pt;
    margin: 0;
    color: #1e221b;
  }
  .header .meta {
    font-size: 8.5pt;
    color: #666;
    margin-top: 4px;
  }
  .score-card {
    background: #f8f6f0;
    border: 1px solid #e2d9cc;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .score-num {
    font-size: 34pt;
    font-weight: 700;
    color: #c88750;
    line-height: 1;
  }
  .score-grade {
    font-size: 13pt;
    font-weight: 600;
    color: #333;
  }
  .ai-summary {
    background: #fdfbf7;
    border-left: 4px solid #c88750;
    padding: 10px 14px;
    margin-bottom: 20px;
    font-size: 9.5pt;
    color: #2b2b2b;
  }
  h2 {
    font-size: 13pt;
    border-bottom: 1px solid #ddd;
    padding-bottom: 5px;
    margin-top: 20px;
    margin-bottom: 12px;
    color: #1e221b;
  }
  .finding {
    border: 1px solid #e2e0d7;
    border-radius: 6px;
    margin-bottom: 12px;
    padding: 10px 14px;
    page-break-inside: avoid;
    background: #ffffff;
  }
  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-Critical { background: #fee2e2; color: #b91c1c; }
  .badge-High { background: #ffedd5; color: #c2410c; }
  .badge-Medium { background: #fef3c7; color: #b45309; }
  .badge-Low { background: #f0fdf4; color: #15803d; }
  
  .compliance-tag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 7pt;
    font-weight: 600;
    border: 1px solid #c88750;
    color: #8c5324;
    background: #fbf5ee;
    margin-left: 4px;
    vertical-align: middle;
  }
  
  .finding-title {
    font-size: 11pt;
    font-weight: 600;
    margin-left: 6px;
    color: #1a1a1a;
  }
  .finding-meta {
    font-size: 8.5pt;
    color: #777;
    margin-top: 2px;
  }
  .remediation-preview {
    margin-top: 8px;
    border-top: 1px dashed #e2e0d7;
    padding-top: 8px;
  }
  .remediation-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 8px 0;
    margin-top: 4px;
  }
  .remediation-cell {
    width: 50%;
    vertical-align: top;
    padding: 0;
  }
  .code-box {
    border-radius: 4px;
    padding: 8px 10px;
    font-family: Consolas, "Courier New", monospace;
    font-size: 8pt;
    line-height: 1.35;
    white-space: pre-wrap;
    word-break: break-all;
    min-height: 38px;
  }
  .code-box-before {
    background: #fff5f5;
    border: 1px solid #fecaca;
    color: #991b1b;
  }
  .code-box-after {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
  }
  .box-label {
    font-size: 7pt;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 3px;
  }
  .label-before { color: #b91c1c; }
  .label-after { color: #15803d; }
  
  .code-block {
    background: #111310;
    color: #d8d4c9;
    padding: 12px;
    border-radius: 6px;
    font-family: Consolas, monospace;
    font-size: 8pt;
    white-space: pre-wrap;
  }
  .footer {
    margin-top: 30px;
    font-size: 7.5pt;
    color: #999;
    text-align: center;
    border-top: 1px solid #eee;
    padding-top: 8px;
  }
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>IPsec Security Assessment</h1>
      <div class="meta">Target: <b>{{ file_name }}</b> | Scan: <b>{{ scan_name }}</b> | Date: {{ analyzed_at }}</div>
    </div>
  </div>

  <div class="score-card">
    <div>
      <div class="score-num">{{ score }}</div>
      <div class="score-grade">{{ grade }}</div>
    </div>
    <div style="flex: 1; padding-left: 18px; border-left: 1px solid #e5dfd5;">
      <div><b>Executive Overview &amp; Severity Distribution</b></div>
      <div style="font-size: 8.5pt; color: #666; margin-top: 4px;">
        Critical: <b>{{ severity_counts.Critical }}</b> &nbsp;|&nbsp;
        High: <b>{{ severity_counts.High }}</b> &nbsp;|&nbsp;
        Medium: <b>{{ severity_counts.Medium }}</b> &nbsp;|&nbsp;
        Low: <b>{{ severity_counts.Low }}</b>
      </div>
    </div>
  </div>

  <div class="ai-summary">
    <strong>Executive Security Assessment:</strong><br/>
    {{ ai_summary }}
  </div>

  <h2>Security Findings &amp; Remediation Diff ({{ findings|length }})</h2>
  {% for f in findings %}
  <div class="finding">
    <div>
      <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="finding-meta">— {{ f.category }}</span>
      {% if f.compliance_tags %}
        {% for tag in f.compliance_tags %}
          <span class="compliance-tag">{{ tag }}</span>
        {% endfor %}
      {% endif %}
    </div>
    <p style="margin: 6px 0; font-size: 9pt; color: #444;">{{ f.explanation }}</p>

    <div class="remediation-preview">
      <table class="remediation-table">
        <tr>
          <td class="remediation-cell">
            <div class="box-label label-before">Detected Configuration (Before)</div>
            <div class="code-box code-box-before">{{ f.detected_config_line or f.detected }}</div>
          </td>
          <td class="remediation-cell">
            <div class="box-label label-after">Recommended Fix (After - Compliant)</div>
            <div class="code-box code-box-after">{{ f.recommended_config_line or f.recommended }}</div>
          </td>
        </tr>
      </table>
    </div>
  </div>
  {% endfor %}

  {% if technical_details %}
  <h2>Technical Details / Extracted Proposal</h2>
  <div class="code-block">{{ technical_details }}</div>
  {% endif %}

  <div class="footer">
    Generated by CipherLens IPsec Protocol Analyzer · Confidential &amp; Proprietary Security Report
  </div>
</body>
</html>
"""


def generate_pdf(report_id: str, scan_data: Dict[str, Any]) -> str:
    """
    Renders the report HTML and saves as a PDF file in reports_storage/{report_id}.pdf.
    Returns the absolute path to the generated PDF file.
    """
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")

    template = Template(REPORT_HTML_TEMPLATE)
    html_content = template.render(
        scan_name=scan_data.get("scanName", "IPsec Security Review"),
        file_name=scan_data.get("fileName", "configuration.conf"),
        analyzed_at=scan_data.get("analyzedAt", "Sep 23, 2026"),
        score=scan_data.get("score", 0),
        grade=scan_data.get("grade", "Grade F"),
        severity_counts=scan_data.get("severityCounts", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}),
        ai_summary=scan_data.get("aiSummary", ""),
        findings=scan_data.get("findings", []),
        technical_details=scan_data.get("technicalDetails", ""),
    )

    try:
        import importlib
        weasyprint_mod = importlib.import_module("weasyprint")
        weasyprint_mod.HTML(string=html_content).write_pdf(pdf_path)
    except Exception as e:
        # Fallback if WeasyPrint or native GTK cdlls are not installed on the OS
        print(f"[PDF Generator] WeasyPrint generation fallback due to: {e}")
        _generate_fallback_pdf(pdf_path, scan_data, html_content)

    return pdf_path


def _generate_fallback_pdf(pdf_path: str, scan_data: Dict[str, Any], html_content: str):
    """
    Fallback generator that creates a valid PDF containing the report summary,
    compliance tags, and remediation preview if WeasyPrint system dependencies are missing.
    """
    title = f"IPsec Security Assessment - {scan_data.get('scanName', 'Review')}"
    score_line = f"Score: {scan_data.get('score', 0)} ({scan_data.get('grade', 'N/A')})"
    summary = scan_data.get("aiSummary", "")

    # Clean minimal PDF format specification
    content_stream = f"""BT
/F1 16 Tf
50 750 Td
({title[:60]}) Tj
/F1 11 Tf
0 -26 Td
({score_line}) Tj
0 -20 Td
(Target File: {scan_data.get('fileName', 'Unknown')}) Tj
0 -22 Td
(Executive AI Summary:) Tj
/F1 9 Tf
0 -16 Td
({summary[:90]}) Tj
0 -14 Td
({summary[90:180]}) Tj
0 -24 Td
/F1 11 Tf
(Security Findings & Remediations:) Tj
/F1 8 Tf
"""
    y_offset = -16
    for f in scan_data.get("findings", [])[:6]:
        tags_str = f" [{', '.join(f.get('compliance_tags', []))}]" if f.get("compliance_tags") else ""
        header_line = f"[{f.get('severity')}] {f.get('title')}{tags_str}"
        det_line = f"  - Before: {f.get('detected_config_line', f.get('detected', ''))[:60]}"
        rec_line = f"  + After:  {f.get('recommended_config_line', f.get('recommended', ''))[:60]}"
        
        content_stream += f"0 {y_offset} Td\n({header_line[:85]}) Tj\n"
        content_stream += f"0 -12 Td\n({det_line}) Tj\n"
        content_stream += f"0 -12 Td\n({rec_line}) Tj\n"
        y_offset = -14

    content_stream += "ET"

    stream_bytes = content_stream.encode("latin-1", "replace")
    pdf_bytes = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(stream_bytes)} >>
stream
{content_stream}
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000234 00000 n 
0000000330 00000 n 
    trailer
<< /Size 6 /Root 1 0 R >>
startxref
412
%%EOF""".encode("latin-1", "replace")

    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

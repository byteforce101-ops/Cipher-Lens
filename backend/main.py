"""
IPsec Analyzer - FastAPI Backend Application
Handles file uploads, protocol/config parsing, security rule auditing,
Gemini AI assessment, scoring, and PDF report delivery.
"""

import os
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from ai.explainer import generate_ai_assessment
from engine.rules import evaluate_rules
from engine.scorer import calculate_score
from parser.config_parser import parse_config_file
from parser.pcap_parser import parse_pcap_file
from reports.pdf_generator import REPORTS_DIR, generate_pdf

# Load environment variables
load_dotenv()

app = FastAPI(
    title="IPsec Analyzer API",
    description="Automated IPsec configuration and packet capture security auditor with AI assessment",
    version="1.0.0",
)

# CORS configuration
origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows localhost:3000 and any dev origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "IPsec Analyzer API",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    scanName: Optional[str] = Form(None),
):
    """
    Analyzes an uploaded IPsec VPN configuration or packet capture file (.conf, .cfg, .txt, .pcap, .pcapng).
    Returns findings, security score, grade, and AI executive summary.
    """
    filename = file.filename or "uploaded_file"
    ext = os.path.splitext(filename)[1].lower()
    allowed_exts = [".conf", ".cfg", ".txt", ".pcap", ".pcapng"]

    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed types: {', '.join(allowed_exts)}",
        )

    # Temporary storage for parsing
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, filename)

    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 1. Route to correct parser based on file extension
        if ext in [".pcap", ".pcapng"]:
            parsed_data = parse_pcap_file(temp_file_path, filename)
        else:
            with open(temp_file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            parsed_data = parse_config_file(content, filename)

        # 2. Run rule engine to generate findings
        findings = evaluate_rules(parsed_data)

        # 3. Calculate score & grade
        score, grade, severity_counts = calculate_score(findings)

        # 4. Enrich with Gemini AI assessment
        ai_data = generate_ai_assessment(
            findings=findings,
            filename=filename,
            score=score,
            grade=grade,
        )
        ai_summary = ai_data.get("aiSummary", "")
        enriched_findings = ai_data.get("findings", findings)

        # 5. Format scan metadata matching frontend
        report_id = f"rep_{uuid.uuid4().hex[:10]}"
        now = datetime.now()
        analyzed_at = now.strftime("%b %d, %Y")

        result = {
            "reportId": report_id,
            "scanName": (scanName and scanName.strip()) or f"Scan: {filename}",
            "fileName": filename,
            "analyzedAt": analyzed_at,
            "score": score,
            "grade": grade,
            "severityCounts": severity_counts,
            "aiSummary": ai_summary,
            "findings": enriched_findings,
            "technicalDetails": parsed_data.get("technical_snippet", ""),
        }

        # 6. Generate and save PDF report
        try:
            generate_pdf(report_id, result)
        except Exception as e:
            print(f"[Warning] PDF generation failed: {e}")

        # 7. Return exact JSON shape expected by frontend Results component
        return JSONResponse(content=result)

    finally:
        # Clean up temporary upload file
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.api_route("/api/reports/{report_id}.pdf", methods=["GET", "HEAD"])
async def get_report_pdf(report_id: str):
    """
    Serves the generated PDF report for the given report ID.
    """
    pdf_filename = f"{report_id}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    if not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=404,
            detail=f"Report PDF with ID '{report_id}' not found.",
        )

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"IPsec-Assessment-{report_id}.pdf",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

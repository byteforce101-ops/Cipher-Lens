"""
AI Explainer service using the Google Gemini API.
Enriches security findings with clear, plain-English executive explanations and remediation advice.
"""

import json
import os
from typing import Any, Dict, List


def generate_ai_assessment(
    findings: List[Dict[str, str]],
    filename: str,
    score: int,
    grade: str
) -> Dict[str, Any]:
    """
    Calls Gemini API (if GEMINI_API_KEY is configured) to generate an executive AI summary
    and contextual explanations. Falls back gracefully to expert templates if unavailable.
    """
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    
    # Check if a real key is present
    if gemini_api_key and gemini_api_key.strip() and gemini_api_key != "your_gemini_api_key_here":
        try:
            import google.generativeai as genai

            genai.configure(api_key=gemini_api_key.strip())
            model = genai.GenerativeModel("gemini-1.5-flash")

            prompt = f"""You are a senior network cybersecurity analyst reviewing an IPsec VPN configuration/packet capture.
File: {filename}
Score: {score}/100 ({grade})
Findings identified:
{json.dumps(findings, indent=2)}

Please provide:
1. A concise, 2-3 sentence executive summary suitable for a CISO or network admin detailing the overall risk posture and immediate priority.
2. If appropriate, refine the explanation of the top findings.

Return your response in strictly valid JSON format with this exact structure:
{{
  "aiSummary": "2-3 sentence executive assessment...",
  "refinedExplanations": {{
    "title_of_finding": "plain English explanation"
  }}
}}
Do NOT include markdown formatting or backticks around the JSON.
"""
            response = model.generate_content(prompt)
            text = response.text.strip()
            
            # Strip any markdown code fences if model returned them
            if text.startswith("```"):
                text = text.strip("`")
                if text.startswith("json"):
                    text = text[4:].strip()

            parsed_ai = json.loads(text)
            summary = parsed_ai.get("aiSummary")
            refined = parsed_ai.get("refinedExplanations", {})

            if summary:
                # Enrich findings with refined explanations if provided
                for f in findings:
                    if f["title"] in refined:
                        f["explanation"] = refined[f["title"]]
                return {"aiSummary": summary, "findings": findings}

        except Exception as e:
            # Fallback to deterministic expert summary
            print(f"[AI Explainer Warning] Gemini API call bypassed or failed: {e}")

    # Fallback contextual summary
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    other_count = len(findings) - (crit_count + high_count)

    if crit_count > 0:
        ai_summary = (
            f"Your tunnel is operational but carries meaningful authentication and cryptographic risk. "
            f"{crit_count} critical issue{'s' if crit_count > 1 else ''} should be resolved immediately, "
            f"while {high_count + other_count} additional improvement{'s' if (high_count + other_count) > 1 else ''} will materially strengthen the configuration."
        )
    elif high_count > 0:
        ai_summary = (
            f"The analyzed IPsec parameters demonstrate modern baseline compliance, but exhibit {high_count} elevated risk item{'s' if high_count > 1 else ''}. "
            f"Upgrading key negotiation parameters will prevent downgrade attacks."
        )
    else:
        ai_summary = (
            f"The VPN configuration demonstrates strong adherence to contemporary cryptographic standards. "
            f"Only minor tuning recommendations were identified."
        )

    return {"aiSummary": ai_summary, "findings": findings}

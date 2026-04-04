import json
import logging
import uuid
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import io

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import groq
from openai import OpenAI
import google.generativeai as genai
from utils import generate_pdf_report
import zipfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CodeGuard AI Backend API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for reports (so GET /export-pdf works statelessly for the client)
REPORT_CACHE: Dict[str, Dict[str, Any]] = {}

def call_ollama(prompt: str, system_prompt: str) -> str:
    """Fallback to local Ollama API"""
    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3.2", # or another default model
            "prompt": prompt,
            "system": system_prompt,
            "stream": False
        }, timeout=60)
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama connection failed: {e}")
        return '{"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": "unknown", "issue_description": "Failed to connect to Ollama. Ensure Ollama is running.", "suggested_fix": "Start Ollama via command line."}]}'

def call_openai(prompt: str, system_prompt: str, api_key: str) -> str:
    """Call OpenAI API (GPT-4 or GPT-3.5)"""
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=1024,
            response_format={"type": "json_object"}
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API Error: {e}")
        return '{"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": "unknown", "issue_description": f"OpenAI Error: {str(e)}", "suggested_fix": "Check API key or rate limits."}]}'

def call_gemini(prompt: str, system_prompt: str, api_key: str) -> str:
    """Call Google Gemini API"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        combined_prompt = f"{system_prompt}\n\n{prompt}"
        response = model.generate_content(combined_prompt)
        
        # Extract JSON from response
        if response.text:
            text = response.text.strip()
            # Try to parse JSON directly
            if text.startswith('{'):
                return text
            # Try to extract JSON from markdown code block
            if "```json" in text:
                json_str = text.split("```json")[-1].split("```")[0].strip()
                return json_str
            # Return formatted error if response is not JSON
            return json.dumps({
                "status": "ERROR",
                "stats": {"High": 0, "Medium": 0, "Low": 0},
                "findings": [{
                    "file_name": "unknown",
                    "issue_description": "Gemini response was not properly formatted JSON",
                    "suggested_fix": f"Raw response: {text[:500]}"
                }]
            })
        return '{"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": "unknown", "issue_description": "No response from Gemini", "suggested_fix": "Try again or use a different provider."}]}'
    except Exception as e:
        logger.error(f"Gemini API Error: {e}")
        return '{"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": "unknown", "issue_description": f"Gemini Error: {str(e)}", "suggested_fix": "Check API key or rate limits."}]}'

def sort_findings_by_severity(findings: List[dict]) -> List[dict]:
    """Sort findings by severity: High > Medium > Low"""
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    
    def get_severity(finding: dict) -> int:
        # Extract severity from the finding if available
        desc = finding.get("issue_description", "").upper()
        if "HIGH" in desc:
            return 0
        elif "MEDIUM" in desc:
            return 1
        else:
            return 2
    
    return sorted(findings, key=get_severity)

def parse_ai_response(ai_text: str, filename: str) -> dict:
    try:
        if "```json" in ai_text:
            json_str = ai_text.split("```json")[-1].split("```")[0].strip()
            parsed = json.loads(json_str)
        else:
            parsed = json.loads(ai_text)
        
        # Sort findings by severity
        if "findings" in parsed:
            parsed["findings"] = sort_findings_by_severity(parsed["findings"])
        
        return parsed
    except Exception as e:
        logger.error(f"Failed to parse JSON directly: {ai_text}")
        status = "VULNERABLE" if "[STATUS: VULNERABLE]" in ai_text.upper() or "VULNERABLE" in ai_text.upper() else "SAFE"
        counts = {"High": ai_text.upper().count("HIGH"), "Medium": ai_text.upper().count("MEDIUM"), "Low": ai_text.upper().count("LOW")}
        
        return {
            "status": status,
            "stats": counts,
            "findings": [{
                "file_name": filename,
                "issue_description": "Raw Response (Could not parse proper JSON)",
                "suggested_fix": ai_text[:500] + "..."
            }]
        }

def analyze_code_logic(filename: str, content: str, api_key: str, persona: str):
    if "Student" in persona:
        system_rules = (
            "You are a helpful Security Tutor for students. "
            "Your output MUST BE valid JSON strictly with the following schema: "
            "{ 'status': 'SAFE' or 'VULNERABLE', 'stats': {'High': 0, 'Medium': 0, 'Low': 0}, 'findings': [{'file_name': 'filename', 'issue_description': 'desc', 'suggested_fix': 'fix'}] }. "
            "Encourage learning. If code has minor issues, mark as SAFE but list issues in findings."
        )
        current_temp = 0.3
    else:
        system_rules = (
            "You are a Senior Lead Cyber-Security Auditor. Be RUTHLESS. "
            "Your output MUST BE valid JSON strictly with the following schema: "
            "{ 'status': 'SAFE' or 'VULNERABLE', 'stats': {'High': int, 'Medium': int, 'Low': int}, 'findings': [{'file_name': 'filename', 'issue_description': 'desc', 'suggested_fix': 'fix'}] }. "
            "Any minor risk or lack of validation MUST be marked VULNERABLE."
        )
        current_temp = 0.1

    user_prompt = f"File: {filename}\nPersona Context: {persona}\nCode Content:\n{content}"

    try:
        # Route based on API key prefix
        if api_key:
            api_key_str = str(api_key).strip()
            
            if api_key_str.startswith("gsk_"):
                # Groq API
                try:
                    client = groq.Groq(api_key=api_key_str)
                    completion = client.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[
                            {"role": "system", "content": system_rules},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=current_temp,
                        max_tokens=1024,
                        response_format={"type": "json_object"}
                    )
                    ai_output = completion.choices[0].message.content
                except Exception as e:
                    logger.error(f"Groq API Error: {e}")
                    return {"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": filename, "issue_description": f"Groq Error: {str(e)}", "suggested_fix": "Check API key or Rate Limits."}]}
            
            elif api_key_str.startswith("sk-"):
                # OpenAI API
                ai_output = call_openai(user_prompt, system_rules, api_key_str)
            
            elif api_key_str.startswith("AIzaSy"):
                # Google Gemini API
                ai_output = call_gemini(user_prompt, system_rules, api_key_str)
            
            else:
                # Unknown API key format, fallback to Ollama
                logger.warning(f"Unknown API key format, falling back to Ollama")
                ai_output = call_ollama(user_prompt, system_rules)
        else:
            # No API key provided, use Ollama
            ai_output = call_ollama(user_prompt, system_rules)

    except Exception as e:
        logger.error(f"Unexpected error in analyze_code_logic: {e}")
        return {"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": filename, "issue_description": f"Analysis Error: {str(e)}", "suggested_fix": "Try again or contact support."}]}

    return parse_ai_response(ai_output, filename)

def combine_results(results_list: List[dict]):
    total_stats = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0, "Vuln": 0}
    all_findings = []
    
    for res in results_list:
        status = res.get("status", "SAFE")
        if status.upper() == "SAFE":
            total_stats["Safe"] += 1
        else:
            total_stats["Vuln"] += 1
        
        s = res.get("stats", {})
        total_stats["High"] += int(s.get("High", 0))
        total_stats["Medium"] += int(s.get("Medium", 0))
        total_stats["Low"] += int(s.get("Low", 0))
        
        all_findings.extend(res.get("findings", []))
    
    # Sort all findings by severity
    all_findings = sort_findings_by_severity(all_findings)
    
    final_status = "VULNERABLE" if total_stats["Vuln"] > 0 else "SAFE"
    
    # Organize findings by file
    findings_by_file = {}
    for finding in all_findings:
        filename = finding.get("file_name", "unknown")
        if filename not in findings_by_file:
            findings_by_file[filename] = []
        findings_by_file[filename].append(finding)
    
    return {
        "status": final_status,
        "stats": total_stats,
        "findings": all_findings,
        "findings_by_file": findings_by_file
    }

def process_file_content(files: List[UploadFile]) -> List[Dict]:
    files_to_scan = []
    
    for file in files:
        if not file.filename:
            continue
            
        content_bytes = file.file.read()
        
        if file.filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
                    for z_filename in z.namelist():
                        ext = z_filename.split('.')[-1].lower()
                        if ext in ['py', 'cpp', 'h', 'js', 'ts', 'tsx', 'jsx'] and not z_filename.startswith('__'):
                            with z.open(z_filename) as internal_file:
                                files_to_scan.append({
                                    "name": z_filename,
                                    "content": internal_file.read().decode("utf-8", errors="ignore")
                                })
            except Exception as e:
                logger.error(f"ZIP parsing error for {file.filename}: {e}")
        else:
            files_to_scan.append({
                "name": file.filename,
                "content": content_bytes.decode("utf-8", errors="ignore")
            })
            
    return files_to_scan

@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze_endpoint(
    request: Request,
    files: List[UploadFile] = File(...),
    persona: str = Form("Student"),
    api_key: Optional[str] = Form(None)
):
    try:
        files_to_scan = process_file_content(files)
        if not files_to_scan:
             return JSONResponse(status_code=400, content={"message": "No valid source files found or invalid format."})
             
        individual_results = []
        for f in files_to_scan:
            res = analyze_code_logic(f["name"], f["content"], api_key, persona)
            individual_results.append(res)
            
        combined = combine_results(individual_results)
        
        report_id = str(uuid.uuid4())
        
        pdf_results = [{"name": f.get("file_name", "unknown"), "safe": combined["status"] == "SAFE", "report": f.get("issue_description", "") + " - Fix: " + f.get("suggested_fix", "")} for f in combined["findings"]]
        
        REPORT_CACHE[report_id] = {
            "results": pdf_results,
            "stats": combined["stats"],
            "persona": persona
        }
        
        return JSONResponse(content={
            "report_id": report_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "findings": combined["findings"]
        })
        
    except Exception as e:
        logger.error(f"Error processing analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/export-pdf")
@limiter.limit("10/minute")
async def export_pdf_endpoint(request: Request, report_id: str):
    cached = REPORT_CACHE.get(report_id)
    if not cached:
        raise HTTPException(status_code=404, detail="Report ID not found or expired")
        
    pdf_bytes = generate_pdf_report(cached["results"], cached["stats"], cached["persona"])
    
    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="Failed to generate PDF")
        
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_report_{report_id[:8]}.pdf"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

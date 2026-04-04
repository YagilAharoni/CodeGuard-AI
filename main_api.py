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

def parse_ai_response(ai_text: str, filename: str) -> dict:
    try:
        if "```json" in ai_text:
            json_str = ai_text.split("```json")[-1].split("```")[0].strip()
            return json.loads(json_str)
        return json.loads(ai_text)
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

    if api_key and str(api_key).startswith("gsk_"):
        try:
            client = groq.Groq(api_key=api_key)
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
    else:
        ai_output = call_ollama(user_prompt, system_rules)

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
        
    final_status = "VULNERABLE" if total_stats["Vuln"] > 0 else "SAFE"
    
    return {
        "status": final_status,
        "stats": total_stats,
        "findings": all_findings
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
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)

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

@app.get("/")
async def root():
    """Root endpoint - API status"""
    return {
        "message": "CodeGuard AI Backend API is running",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "analyze": "POST /analyze - Upload files for security analysis",
            "export_pdf": "GET /export-pdf - Download PDF report"
        }
    }

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

def call_groq(prompt: str, system_prompt: str, api_key: str, temperature: float = 0.3) -> str:
    """Call Groq API"""
    try:
        client = groq.Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=1024,
            response_format={"type": "json_object"}
        )
        return completion.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq API Error: {e}")
        return '{"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": "unknown", "issue_description": f"Groq Error: {str(e)}", "suggested_fix": "Check API key or rate limits."}]}'

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

def analyze_code_logic(filename: str, content: str, api_key: str, persona: str, provider: str = None):
    if "Student" in persona:
        system_rules = (
            "You are a helpful Security Tutor for students. Your goal is to encourage learning and growth. "
            "You MUST respond with ONLY valid JSON (no markdown, no extra text) following this exact schema:\n"
            "{\n"
            "  'status': 'SAFE' or 'VULNERABLE',\n"
            "  'stats': {'High': 0, 'Medium': 0, 'Low': 0},\n"
            "  'findings': [{'file_name': 'filename', 'issue_description': 'issue description', 'suggested_fix': 'recommended fix'}],\n"
            "  'improvement_suggestions': ['suggestion1', 'suggestion2', 'suggestion3']\n"
            "}\n\n"
            "IMPORTANT:\n"
            "- If code has minor issues, mark as SAFE but list them in findings\n"
            "- Only mark VULNERABLE if there's a severe, exploitable security risk\n"
            "- For each finding, start the issue_description with severity in brackets: [HIGH], [MEDIUM], or [LOW]\n"
            "- Provide 2-3 constructive improvement_suggestions for code quality and best practices\n"
            "- Be encouraging and educational in your descriptions"
        )
        current_temp = 0.3
    else:
        system_rules = (
            "You are a Senior Lead Cyber-Security Auditor. Be RUTHLESS and thorough. "
            "You MUST respond with ONLY valid JSON (no markdown, no extra text) following this exact schema:\n"
            "{\n"
            "  'status': 'SAFE' or 'VULNERABLE',\n"
            "  'stats': {'High': 0, 'Medium': 0, 'Low': 0},\n"
            "  'findings': [{'file_name': 'filename', 'issue_description': 'issue description', 'suggested_fix': 'recommended fix'}]\n"
            "}\n\n"
            "IMPORTANT:\n"
            "- If there is ANY risk, lack of validation, hardcoded secrets, or best practice violation, mark VULNERABLE\n"
            "- Count issues by severity: High, Medium, Low\n"
            "- For each finding, start the issue_description with severity in brackets: [HIGH], [MEDIUM], or [LOW]\n"
            "- Production-grade code must be bulletproof\n"
            "- Be explicit and detailed about every vulnerability\n"
            "- Do NOT be lenient with professional code"
        )
        current_temp = 0.1

    user_prompt = (
        f"Analyze the following file for security vulnerabilities.\n\n"
        f"File: {filename}\n"
        f"Persona Context: {persona}\n\n"
        f"Report Requirements:\n"
        f"1. Start your response with either '[STATUS: SAFE]' or '[STATUS: VULNERABLE]'.\n"
        f"2. Provide a 'Security Summary'.\n"
        f"3. List 'Vulnerability Details' - for each issue, start with severity level (HIGH/MEDIUM/LOW) in brackets.\n"
        f"4. Provide 'Recommended Code Fixes'.\n"
        f"{'5. Suggest 2-3 ways to improve this project (for learning purposes).' if 'Student' in persona else ''}\n\n"
        f"Code Content:\n"
        f"---\n"
        f"{content}\n"
        f"---\n\n"
        f"RESPOND WITH ONLY VALID JSON, NO MARKDOWN CODE BLOCKS, NO EXTRA TEXT."
    )

    try:
        # Route based on provider selection or API key prefix
        if provider and provider != "auto":
            # Manual provider selection
            logger.info(f"[{filename}] Manual provider selection: {provider}")
            if provider == "groq":
                ai_output = call_groq(user_prompt, system_rules, api_key, current_temp)
            elif provider == "openai":
                ai_output = call_openai(user_prompt, system_rules, api_key)
            elif provider == "gemini":
                ai_output = call_gemini(user_prompt, system_rules, api_key)
            elif provider == "ollama":
                ai_output = call_ollama(user_prompt, system_rules)
            else:
                logger.warning(f"[{filename}] Unknown provider: {provider}, falling back to Ollama")
                ai_output = call_ollama(user_prompt, system_rules)
        else:
            # Auto-detection based on API key prefix
            if api_key and str(api_key).strip():  # Better null/empty check
                api_key_str = str(api_key).strip()
                logger.info(f"[{filename}] API Key received and not empty: {api_key_str[:15]}...")
                logger.info(f"[{filename}] Checking API key prefix...")
                
                if api_key_str.startswith("gsk_"):
                    logger.info(f"[{filename}] ✓ Detected Groq API key")
                    ai_output = call_groq(user_prompt, system_rules, api_key_str, current_temp)
                
                elif api_key_str.startswith("sk-"):
                    logger.info(f"[{filename}] ✓ Detected OpenAI API key")
                    ai_output = call_openai(user_prompt, system_rules, api_key_str)
                
                elif api_key_str.startswith("AIzaSy"):
                    logger.info(f"[{filename}] ✓ Detected Google Gemini API key")
                    ai_output = call_gemini(user_prompt, system_rules, api_key_str)
                
                else:
                    # Unknown API key format, fallback to Ollama
                    logger.warning(f"[{filename}] ✗ Unknown API key format: {api_key_str[:20]}..., falling back to Ollama")
                    ai_output = call_ollama(user_prompt, system_rules)
            else:
                # No API key provided, use Ollama
                logger.info(f"[{filename}] No API key provided or empty, using Ollama")
                ai_output = call_ollama(user_prompt, system_rules)

    except Exception as e:
        logger.error(f"Unexpected error in analyze_code_logic: {e}")
        return {"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": filename, "issue_description": f"Analysis Error: {str(e)}", "suggested_fix": "Try again or contact support."}]}

    return parse_ai_response(ai_output, filename)

def combine_results(results_list: List[dict]):
    total_stats = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0, "Vuln": 0, "Error": 0}
    all_findings = []
    all_improvement_suggestions = []
    has_errors = False
    
    for res in results_list:
        status = res.get("status", "SAFE").upper()
        if status == "SAFE":
            total_stats["Safe"] += 1
        elif status == "ERROR":
            total_stats["Error"] += 1
            has_errors = True
        else:
            total_stats["Vuln"] += 1
        
        s = res.get("stats", {})
        total_stats["High"] += int(s.get("High", 0))
        total_stats["Medium"] += int(s.get("Medium", 0))
        total_stats["Low"] += int(s.get("Low", 0))
        
        all_findings.extend(res.get("findings", []))
        
        # Collect improvement suggestions (for Student persona)
        if "improvement_suggestions" in res and res["improvement_suggestions"]:
            all_improvement_suggestions.extend(res["improvement_suggestions"])
    
    # Sort all findings by severity
    all_findings = sort_findings_by_severity(all_findings)
    
    # Determine final status: ERROR > VULNERABLE > SAFE
    # VULNERABLE if ANY vulnerabilities found (even 1 medium risk)
    if has_errors:
        final_status = "ERROR"
    elif total_stats["High"] > 0 or total_stats["Medium"] > 0 or total_stats["Low"] > 0:
        final_status = "VULNERABLE"
    else:
        final_status = "SAFE"
    
    # Organize findings by file
    findings_by_file = {}
    for finding in all_findings:
        filename = finding.get("file_name", "unknown")
        if filename not in findings_by_file:
            findings_by_file[filename] = []
        findings_by_file[filename].append(finding)
    
    result = {
        "status": final_status,
        "stats": total_stats,
        "findings": all_findings,
        "findings_by_file": findings_by_file
    }
    
    # Add improvement suggestions if any exist
    if all_improvement_suggestions:
        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for s in all_improvement_suggestions:
            if s not in seen:
                unique_suggestions.append(s)
                seen.add(s)
        result["improvement_suggestions"] = unique_suggestions
    
    return result

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
    api_key: Optional[str] = Form(None),
    provider: Optional[str] = Form(None)
):
    try:
        logger.info(f"=== ANALYZE REQUEST START ===")
        logger.info(f"API Key received: {api_key}")
        logger.info(f"API Key type: {type(api_key)}")
        logger.info(f"API Key is None: {api_key is None}")
        logger.info(f"API Key is empty: {api_key == ''}")
        if api_key:
            logger.info(f"API Key first 20 chars: {api_key[:20]}")
        logger.info(f"Persona: {persona}")
        logger.info(f"Provider: {provider}")
        
        # Generate unique report ID
        report_id = str(uuid.uuid4())
        logger.info(f"Generated Report ID: {report_id}")
        
        files_to_scan = process_file_content(files)
        logger.info(f"Files to scan: {len(files_to_scan)}")
        
        if not files_to_scan:
            return JSONResponse(status_code=400, content={"message": "No valid source files found or invalid format."})
             
        individual_results = []
        for f in files_to_scan:
            logger.info(f"Analyzing file: {f['name']} with API KEY: {api_key[:10] if api_key else 'NONE'}...")
            res = analyze_code_logic(f["name"], f["content"], api_key, persona, provider)
            individual_results.append(res)
        
        # Combine all individual results into a single report
        combined = combine_results(individual_results)
        
        # Create PDF results - one entry per file, not per finding
        pdf_results = []
        for filename, findings in combined["findings_by_file"].items():
            # Determine if this file is safe (no findings = safe)
            file_safe = len(findings) == 0
            # Combine all findings for this file into one report
            file_report = "\n".join([f"{f.get('issue_description', '')} - Fix: {f.get('suggested_fix', '')}" for f in findings])
            if not file_report:
                file_report = "No vulnerabilities found."
            
            pdf_results.append({
                "name": filename,
                "safe": file_safe,
                "report": file_report
            })
        
        REPORT_CACHE[report_id] = {
            "results": pdf_results,
            "stats": combined["stats"],
            "persona": persona,
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        }
        
        return JSONResponse(content={
            "report_id": report_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "findings": combined["findings"],
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        })
        
    except Exception as e:
        logger.error(f"Error processing analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/export-pdf")
@limiter.limit("10/minute")
async def export_pdf_endpoint(request: Request, report_id: str):
    logger.info(f"=== PDF EXPORT REQUEST ===")
    logger.info(f"Report ID: {report_id}")
    
    cached = REPORT_CACHE.get(report_id)
    if not cached:
        logger.error(f"Report ID {report_id} not found in cache")
        raise HTTPException(status_code=404, detail="Report ID not found or expired")
    
    logger.info(f"Cached data keys: {list(cached.keys())}")
    logger.info(f"Persona: {cached.get('persona')}")
    logger.info(f"Results count: {len(cached.get('results', []))}")
    logger.info(f"Improvement suggestions: {cached.get('improvement_suggestions', [])}")
    
    try:
        pdf_bytes = generate_pdf_report(cached["results"], cached["stats"], cached["persona"], cached.get("improvement_suggestions", []))
        logger.info(f"PDF generation result: {pdf_bytes is not None}")
        
        if not pdf_bytes:
            logger.error("PDF generation returned None")
            raise HTTPException(status_code=500, detail="Failed to generate PDF")
            
        logger.info(f"PDF size: {len(pdf_bytes)} bytes")
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{report_id[:8]}.pdf"}
        )
        
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

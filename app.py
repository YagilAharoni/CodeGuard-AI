import json
import logging
import os
import time
import uuid
import threading
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import io
import sqlite3
import bcrypt

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import groq
from openai import OpenAI
from google import genai
from utils import generate_pdf_report
import zipfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Environments & Health ---
ENV_MODE = os.getenv("ENV_MODE", "development")
DEBUG_MODE = ENV_MODE == "development"

# --- Resource Limits ---
MAX_FILES_PER_SCAN = 20          # Maximum number of files allowed per scan
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB per individual file
MAX_TOTAL_SCAN_SIZE = 10 * 1024 * 1024  # 10 MB total across all files

# --- Server-side Default AI Key ---
# Users don't need their own API key — the server provides a Groq key as default.
# Set DEFAULT_GROQ_API_KEY in your Railway environment variables.
DEFAULT_GROQ_API_KEY = os.getenv("DEFAULT_GROQ_API_KEY", "")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CodeGuard AI Backend API", debug=DEBUG_MODE)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000").split(","),
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
            "export_pdf": "GET /export-pdf - Download PDF report",
            "register": "POST /api/register - Register a new user",
            "login": "POST /api/login - Login a user",
            "analyze-github": "POST /analyze-github - Analyze github repo url"
        }
    }

# --- Database Setup ---
DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    login: str  # can be email or username
    password: str

@app.post("/api/register")
async def register(req: RegisterRequest):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # check if user exists
    c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (req.username, req.email))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # hash password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(req.password.encode('utf-8'), salt)
    
    c.execute("""
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
    """, (req.username, req.email, hashed.decode('utf-8')))
    conn.commit()
    conn.close()
    
    return {"message": "User registered successfully"}

@app.post("/api/login")
async def login(req: LoginRequest):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?", (req.login, req.login))
    user = c.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    user_id, username, stored_hash = user
    if not bcrypt.checkpw(req.password.encode('utf-8'), stored_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    return {
        "message": "Login successful",
        "user": {
            "id": user_id,
            "username": username
        }
    }

# In-memory storage for reports (so GET /export-pdf works statelessly for the client)
REPORT_CACHE: Dict[str, Dict[str, Any]] = {}
HISTORY_FILE = "scan_history.json"
history_lock = threading.Lock()


def load_scan_history() -> List[Dict[str, Any]]:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []





def save_scan_history(history: List[Dict[str, Any]]) -> None:
    with history_lock:
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving scan history: {e}")

def append_scan_history(entry: Dict[str, Any]):
    history = load_scan_history()
    
    # 7-day pruning logic
    try:
        from datetime import datetime, timedelta
        now = datetime.now()
        seven_days_ago = now - timedelta(days=7)
        
        # Filter history to keep only entries from the last 7 days
        pruned_history = []
        for h in history:
            try:
                ts_str = h.get("timestamp", "")
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                if ts >= seven_days_ago:
                    pruned_history.append(h)
            except (ValueError, TypeError):
                pruned_history.append(h)
        
        history = pruned_history
    except Exception as e:
        logger.error(f"Error pruning history: {e}")

    history.append(entry)
    save_scan_history(history)

# --- Cache Cleanup Background Task ---
def cleanup_report_cache():
    """Background task to remove old items from REPORT_CACHE"""
    while True:
        try:
            current_time = time.time()
            to_delete = []
            # Use list to avoid 'dictionary changed size during iteration'
            for rid in list(REPORT_CACHE.keys()):
                data = REPORT_CACHE[rid]
                # Items created more than 30 mins ago
                if current_time - data.get("created_at", 0) > 1800:
                    to_delete.append(rid)
            
            for rid in to_delete:
                del REPORT_CACHE[rid]
                
            if to_delete:
                logger.info(f"Background cleanup: Removed {len(to_delete)} expired reports from cache.")
                
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
        
        time.sleep(600) # Run every 10 mins

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_report_cache, daemon=True)
cleanup_thread.start()


def compare_scan_issues(base_findings: List[Dict[str, Any]], compare_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    base_set = { (f.get('file_name', ''), f.get('issue_description', '')) for f in base_findings }
    compare_set = { (f.get('file_name', ''), f.get('issue_description', '')) for f in compare_findings }

    resolved = base_set - compare_set
    new_issues = compare_set - base_set
    unchanged = base_set & compare_set

    return {
        "resolved_count": len(resolved),
        "new_count": len(new_issues),
        "unchanged_count": len(unchanged),
        "resolved_issues": [ {"file_name": fn, "issue_description": desc} for fn, desc in resolved ],
        "new_issues": [ {"file_name": fn, "issue_description": desc} for fn, desc in new_issues ],
        "unchanged_issues": [ {"file_name": fn, "issue_description": desc} for fn, desc in unchanged ]
    }

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
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"Ollama Error: {str(e)}", 
                "suggested_fix": "Start Ollama via command line."
            }]
        })

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
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"OpenAI Error: {str(e)}", 
                "suggested_fix": "Check API key or rate limits."
            }]
        })

def call_gemini(prompt: str, system_prompt: str, api_key: str) -> str:
    """Call Google Gemini API using the new google-genai SDK"""
    try:
        client = genai.Client(api_key=api_key)
        combined_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Use gemini-1.5-flash for better performance and cost-efficiency
        response = client.models.generate_content(
            model='gemini-1.5-flash',
            contents=combined_prompt
        )
        
        # Extract content from response
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
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": "No response from Gemini", 
                "suggested_fix": "Try again or use a different provider."
            }]
        })
    except Exception as e:
        logger.error(f"Gemini API Error: {e}")
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"Gemini Error: {str(e)}", 
                "suggested_fix": "Check API key or rate limits."
            }]
        })

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
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"Groq Error: {str(e)}", 
                "suggested_fix": "Check API key or rate limits."
            }]
        })

def extract_severity(issue_description: str) -> str:
    """Extract severity from the issue description."""
    desc = (issue_description or "").upper()
    if "HIGH" in desc:
        return "High"
    if "MEDIUM" in desc:
        return "Medium"
    if "LOW" in desc:
        return "Low"
    return "Low"


def sort_findings_by_severity(findings: List[dict]) -> List[dict]:
    """Sort findings by severity: High > Medium > Low"""
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    
    def get_severity(finding: dict) -> int:
        severity = extract_severity(finding.get("issue_description", ""))
        return severity_order.get(severity, 2)
    
    return sorted(findings, key=get_severity)


def build_stats_from_findings(findings: List[dict]) -> Dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        counts[extract_severity(finding.get("issue_description", ""))] += 1
    return counts


def parse_ai_response(ai_text: str, filename: str) -> dict:
    try:
        if "```json" in ai_text:
            json_str = ai_text.split("```json")[-1].split("```")[0].strip()
            parsed = json.loads(json_str)
        else:
            parsed = json.loads(ai_text)
        
        if "findings" in parsed:
            parsed["findings"] = sort_findings_by_severity(parsed["findings"])
            parsed["stats"] = build_stats_from_findings(parsed["findings"])
        else:
            parsed["findings"] = []
            parsed["stats"] = {"High": 0, "Medium": 0, "Low": 0}

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
            "  'findings': [{\n"
            "    'file_name': 'filename',\n"
            "    'issue_description': 'issue title with [SEVERITY]',\n"
            "    'root_problem': 'one-sentence explanation of the cause',\n"
            "    'suggested_solution': 'high-level fixing approach',\n"
            "    'fix': 'detailed code correction or remediation steps',\n"
            "    'source_code': 'problematic snippet',\n"
            "    'fixed_code': 'corrected snippet'\n"
            "  }],\n"
            "  'improvement_suggestions': ['suggestion1', 'suggestion2', 'suggestion3']\n"
            "}\n\n"
            "IMPORTANT:\n"
            "- The heart of this application is the solution for each issue. Every finding MUST include a clear, specific fix.\n"
            "- If code has minor issues, mark as SAFE but list them in findings.\n"
            "- Only mark VULNERABLE if there's a severe, exploitable security risk.\n"
            "- For each finding, start the issue_description with severity in brackets: [HIGH], [MEDIUM], or [LOW].\n"
            "- Provide a concrete remediation for each issue, not a generic suggestion.\n"
            "- Provide 2-3 constructive improvement_suggestions for code quality and best practices.\n"
            "- When possible, include source_code with the problematic snippet and fixed_code with the corrected version.\n"
            "- Be encouraging and educational in your descriptions."
        )
        current_temp = 0.3
    else:
        system_rules = (
            "You are a Senior Lead Cyber-Security Auditor. Be RUTHLESS and thorough. "
            "You MUST respond with ONLY valid JSON (no markdown, no extra text) following this exact schema:\n"
            "{\n"
            "  'status': 'SAFE' or 'VULNERABLE',\n"
            "  'stats': {'High': 0, 'Medium': 0, 'Low': 0},\n"
            "  'findings': [{\n"
            "    'file_name': 'filename',\n"
            "    'issue_description': 'issue title with [SEVERITY]',\n"
            "    'root_problem': 'one-sentence explanation of the cause',\n"
            "    'suggested_solution': 'high-level fixing approach',\n"
            "    'fix': 'detailed code correction or remediation steps',\n"
            "    'source_code': 'problematic snippet',\n"
            "    'fixed_code': 'corrected snippet'\n"
            "  }]\n"
            "}\n\n"
            "IMPORTANT:\n"
            "- The heart of this application is the solution for each issue. Every finding MUST include a clear, specific fix.\n"
            "- If there is ANY risk, lack of validation, hardcoded secrets, or best practice violation, mark VULNERABLE.\n"
            "- Count issues by severity: High, Medium, Low.\n"
            "- For each finding, start the issue_description with severity in brackets: [HIGH], [MEDIUM], or [LOW].\n"
            "- Production-grade code must be bulletproof.\n"
            "- Be explicit and detailed about every vulnerability.\n"
            "- When possible, include source_code with the problematic snippet and fixed_code with the corrected version.\n"
            "- Do NOT be lenient with professional code."
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
        f"4. Provide 'Recommended Code Fixes' for every vulnerability. This is the heart of the application.\n"
        f"   Each finding must include a real, actionable suggested_fix with code examples or exact remediation steps.\n"
        f"   Where possible, include 'source_code' with the problematic snippet and 'fixed_code' with the corrected version.\n"
        f"5. Break down every vulnerability into 'Root Problem', 'Suggested Solution', and 'Fix'.\n"
        f"{'6. Suggest 2-3 ways to improve this project (for learning purposes).' if 'Student' in persona else ''}\n\n"
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
                logger.info(f"[{filename}] API Key received and not empty: {api_key_str[:4]}...")
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
        
        all_findings.extend(res.get("findings", []))
        
        # Collect improvement suggestions (for Student persona)
        if "improvement_suggestions" in res and res["improvement_suggestions"]:
            all_improvement_suggestions.extend(res["improvement_suggestions"])
    
    # Sort all findings by severity
    all_findings = sort_findings_by_severity(all_findings)
    
    # Recalculate the final vulnerability counts directly from findings
    calculated_stats = build_stats_from_findings(all_findings)
    total_stats["High"] = calculated_stats["High"]
    total_stats["Medium"] = calculated_stats["Medium"]
    total_stats["Low"] = calculated_stats["Low"]
    
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
    total_size = 0
    
    for file in files:
        if not file.filename:
            continue
            
        # Check total file count
        if len(files_to_scan) >= MAX_FILES_PER_SCAN:
            logger.warning(f"Scan limit reached: maximum {MAX_FILES_PER_SCAN} files allowed.")
            break

        # Check individual file size
        file.file.seek(0, 2)
        size = file.file.tell()
        file.file.seek(0)
        
        if size > MAX_FILE_SIZE:
            logger.warning(f"File {file.filename} too large: {size} bytes. Skipping.")
            continue
            
        total_size += size
        if total_size > MAX_TOTAL_SCAN_SIZE:
            logger.warning("Total scan size limit reached. Skipping remaining files.")
            break

        content_bytes = file.file.read()
        
        if file.filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
                    for z_filename in z.namelist():
                        # Basic path traversal protection
                        if ".." in z_filename or z_filename.startswith("/"):
                            continue
                            
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
@limiter.limit("10/hour")
async def analyze_endpoint(
    request: Request,
    files: List[UploadFile] = File(...),
    persona: str = Form("Student"),
    api_key: Optional[str] = Form(None),
    provider: Optional[str] = Form(None),
    username: Optional[str] = Form(None)
):
    try:
        logger.info(f"=== ANALYZE REQUEST START ===")
        # Resolve effective API key: user-supplied > server default
        effective_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""
        using_server_key = bool(not (api_key or "").strip() and DEFAULT_GROQ_API_KEY)
        logger.info(f"API Key source: {'user-supplied' if not using_server_key else 'server-default-groq'}")
        if effective_key:
            logger.info(f"Effective API Key first 10 chars: {effective_key[:10]}...")
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
            logger.info(f"Analyzing file: {f['name']} with key: {effective_key[:10] if effective_key else 'NONE'}...")
            res = analyze_code_logic(f["name"], f["content"], effective_key, persona, provider)
            individual_results.append(res)
        
        # Combine all individual results into a single report
        combined = combine_results(individual_results)
        combined["created_at"] = time.time()  # For cache cleanup

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
            "results": {
                "status": combined["status"],
                "findings_by_file": combined["findings_by_file"],
            },
            "stats": combined["stats"],
            "persona": persona,
            "username": username or "anonymous",
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        }

        scan_history_entry = {
            "scan_id": report_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "persona": persona,
            "provider": provider or ("auto" if api_key else "ollama"),
            "status": combined["status"],
            "stats": combined["stats"],
            "findings": combined["findings"],
            "findings_by_file": combined["findings_by_file"],
            "username": username or "anonymous",
            "improvement_suggestions": combined.get("improvement_suggestions", []),
            "source": "local_upload"
        }
        append_scan_history(scan_history_entry)
        
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

@app.post("/analyze-github")
@limiter.limit("10/hour")
async def analyze_github_endpoint(
    request: Request,
    github_url: str = Form(...),
    persona: str = Form("Student"),
    api_key: Optional[str] = Form(None),
    provider: Optional[str] = Form(None),
    username: Optional[str] = Form(None)
):
    # Resolve effective API key: user-supplied > server default
    api_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""
    try:
        # Advanced URL parsing: handle both owner/repo and owner/repo/tree/branch
        clean_url = github_url.split('?')[0].rstrip('/')
        url_parts = clean_url.split('/')
        
        # Find the owner and repo indices
        try:
            github_index = next(i for i, part in enumerate(url_parts) if "github.com" in part)
            owner = url_parts[github_index + 1]
            repo = url_parts[github_index + 2]
            
            # Check for specific branch in URL (e.g., /tree/branch_name)
            target_branch = None
            if len(url_parts) > github_index + 4 and url_parts[github_index + 3] == "tree":
                target_branch = url_parts[github_index + 4]
                logger.info(f"Target branch from URL: {target_branch}")
        except (ValueError, IndexError):
            raise HTTPException(status_code=400, detail="Invalid GitHub URL. Use format: https://github.com/owner/repo or https://github.com/owner/repo/tree/branch")

        zip_response = None
        tried_branches = []
        
        # Determine branch to try first
        branches_to_try = []
        if target_branch:
            branches_to_try.append(target_branch)
        else:
            # Try to fetch default branch from GitHub API
            try:
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                api_resp = requests.get(api_url, timeout=10, headers={"User-Agent": "CodeGuard-AI/1.0"})
                if api_resp.status_code == 200:
                    repo_info = api_resp.json()
                    default_branch = repo_info.get("default_branch")
                    if default_branch:
                        logger.info(f"Detected default branch: {default_branch}")
                        branches_to_try.append(default_branch)
                elif api_resp.status_code == 403:
                    logger.warning("GitHub API rate limit hit, falling back to manual branch trial.")
            except Exception as e:
                logger.error(f"Error fetching GitHub default branch: {e}")
        
        # Add fallbacks
        for b in ["main", "master"]:
            if b not in branches_to_try:
                branches_to_try.append(b)

        logger.info(f"Attempting to download from [{owner}/{repo}] branches: {branches_to_try}")

        for branch in branches_to_try:
            try:
                zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
                tried_branches.append(branch)
                resp = requests.get(zip_url, timeout=30, allow_redirects=True, headers={"User-Agent": "CodeGuard-AI/1.0"})
                if resp.status_code == 200:
                    logger.info(f"✓ Found valid branch: {branch}")
                    zip_response = resp
                    break
                elif resp.status_code == 404:
                    continue  # try next branch
                else:
                    logger.warning(f"Unexpected status {resp.status_code} for branch {branch}")
                    continue
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error for branch {branch}: {e}")
                continue
            
        if zip_response is None or zip_response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Could not download repository '{owner}/{repo}'. Tried branches: {', '.join(tried_branches)}. Ensure it is public and valid.")
            
        content_bytes = zip_response.content
        files_to_scan = []
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
            for z_filename in z.namelist():
                ext = z_filename.split('.')[-1].lower()
                if ext in ['py', 'cpp', 'h', 'js', 'ts', 'tsx', 'jsx'] and not z_filename.startswith('__') and "/." not in z_filename and "/node_modules/" not in z_filename:
                    with z.open(z_filename) as internal_file:
                        try:
                            file_content = internal_file.read().decode("utf-8")
                            if file_content.strip():
                                files_to_scan.append({
                                    "name": z_filename,
                                    "content": file_content
                                })
                        except UnicodeDecodeError:
                            pass
                            
        files_to_scan = files_to_scan[:30] # Limit file scan
        report_id = str(uuid.uuid4())
        
        if not files_to_scan:
            return JSONResponse(status_code=400, content={"message": "No valid source files found in repo."})
             
        individual_results = []
        for f in files_to_scan:
            res = analyze_code_logic(f["name"], f["content"], api_key, persona, provider)
            individual_results.append(res)
        
        combined = combine_results(individual_results)
        
        REPORT_CACHE[report_id] = {
            "results": {
                "status": combined["status"],
                "findings_by_file": combined["findings_by_file"],
            },
            "stats": combined["stats"],
            "persona": persona,
            "username": username or "anonymous",
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        }

        scan_history_entry = {
            "scan_id": report_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "persona": persona,
            "provider": provider or ("auto" if api_key else "ollama"),
            "status": combined["status"],
            "stats": combined["stats"],
            "findings": combined["findings"],
            "findings_by_file": combined["findings_by_file"],
            "username": username or "anonymous",
            "improvement_suggestions": combined.get("improvement_suggestions", []),
            "source": f"github:{owner}/{repo}"
        }
        append_scan_history(scan_history_entry)
        
        return JSONResponse(content={
            "report_id": report_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "findings": combined["findings"],
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        })
        
    except Exception as e:
        logger.error(f"Error processing github analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_scan_history(request: Request, username: Optional[str] = None):
    # Authorization check
    auth_user = request.headers.get("X-User")
    if not auth_user or (username and auth_user != username):
        raise HTTPException(status_code=403, detail="Unauthorized access to history")
        
    target_user = username or auth_user
    history = load_scan_history()
    if target_user:
        history = [entry for entry in history if entry.get("username", "anonymous") == target_user]
    return {"history": history[::-1]}  # Return reversed (latest first)

@app.get("/compare")
async def compare_scans(request: Request, scan_a: str, scan_b: str):
    auth_user = request.headers.get("X-User")
    if not auth_user:
         raise HTTPException(status_code=403, detail="Unauthorized access to comparison")

    history = load_scan_history()
    # Filter to only allow comparing scans owned by the user
    user_history = [entry for entry in history if entry.get("username") == auth_user]
    scan_map = {entry.get("scan_id"): entry for entry in user_history}
    
    first = scan_map.get(scan_a)
    second = scan_map.get(scan_b)

    if not first or not second:
        raise HTTPException(status_code=404, detail="One or both scan IDs not found or access denied")

    comparison = compare_scan_issues(first.get("findings", []), second.get("findings", []))
    return {
        "scan_a": first,
        "scan_b": second,
        "comparison": comparison
    }

@app.get("/export-pdf")
@limiter.limit("10/minute")
async def export_pdf_endpoint(request: Request, report_id: str, username: Optional[str] = None):
    auth_user = request.headers.get("X-User")
    if not auth_user:
         raise HTTPException(status_code=403, detail="Unauthorized access to export")

    logger.info(f"=== PDF EXPORT REQUEST ===")
    logger.info(f"Report ID: {report_id}")
    
    cached = REPORT_CACHE.get(report_id)
    
    # Fallback to history if not in cache (e.g. server restart)
    if not cached:
        logger.info(f"Report ID {report_id} not in cache, checking history...")
        history = load_scan_history()
        match = next((h for h in history if h.get("scan_id") == report_id), None)
        
        if match:
            logger.info(f"Found report {report_id} in history fallback.")
            cached = {
                "results": {
                    "status": match.get("status"),
                    "findings_by_file": match.get("findings_by_file"),
                },
                "stats": match.get("stats"),
                "persona": match.get("persona"),
                "username": match.get("username", "anonymous"),
                "improvement_suggestions": match.get("improvement_suggestions", [])
            }
        else:
            logger.error(f"Report ID {report_id} not found in cache or history")
            raise HTTPException(status_code=404, detail="Report ID not found or expired")
    
    logger.info(f"Data available for PDF: Persona={cached.get('persona')}, Results={len(cached.get('results', {}).get('findings_by_file', {}))} files")
    
    try:
        report_username = username or cached.get("username", "anonymous")
        pdf_bytes = generate_pdf_report(cached["results"], cached["stats"], cached["persona"], cached.get("improvement_suggestions", []), report_username)
        logger.info(f"PDF generation result: {pdf_bytes is not None}")
        
        if not pdf_bytes:
            logger.error("PDF generation returned None")
            raise HTTPException(status_code=500, detail="Failed to generate PDF")
            
        # Download filename format: Security Report YYYY-MM-DD HH-mm-ss.pdf
        report_timestamp = time.strftime("%Y-%m-%d %H-%M-%S")
        filename = f"Security Report {report_timestamp}.pdf"
        
        logger.info(f"PDF size: {len(pdf_bytes)} bytes. Exporting as: {filename}")
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
        )
        
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

# ---------------------------------------------------------------------------
# Dependency Vulnerability Scanner
# ---------------------------------------------------------------------------
import re as _re

def parse_dependencies(files_content: List[Dict]) -> Dict[str, List[str]]:
    """
    Parse import/require/include statements from source files.
    Returns a dict: { 'PyPI': [...], 'npm': [...], 'C/C++': [...] }
    """
    ecosystems: Dict[str, set] = {"PyPI": set(), "npm": set(), "C/C++": set()}
    
    for file_entry in files_content:
        name = file_entry.get("name", "")
        content = file_entry.get("content", "")
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        
        if ext == "py":
            # import X, from X import Y
            for m in _re.finditer(r'^(?:import|from)\s+([\w\.]+)', content, _re.MULTILINE):
                pkg = m.group(1).split(".")[0]  # top-level package only
                if pkg and not pkg.startswith("_"):
                    ecosystems["PyPI"].add(pkg)
        elif ext in ("js", "ts", "jsx", "tsx"):
            # require('X') or import ... from 'X'
            for m in _re.finditer(r'''(?:require|from)\s*[\('"]([^\./\'"][^\'"]*)[\'"]''', content):
                pkg = m.group(1).split("/")[0]  # strip sub-paths
                if pkg:
                    ecosystems["npm"].add(pkg)
        elif ext in ("cpp", "c", "h"):
            # #include <X> or #include "X"
            for m in _re.finditer(r'#include\s*[<"]([^>"]+)[>"]', content):
                ecosystems["C/C++"].add(m.group(1))
    
    return {k: sorted(v) for k, v in ecosystems.items() if v}


def query_osv_batch(packages: List[Dict]) -> List[Dict]:
    """Query OSV.dev batch API for vulnerability data."""
    if not packages:
        return []
    try:
        payload = {"queries": packages}
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json=payload,
            timeout=15
        )
        resp.raise_for_status()
        return resp.json().get("results", [])
    except Exception as e:
        logger.error(f"OSV.dev query failed: {e}")
        return []


# Standard library packages to skip (not real dependencies)
STD_LIB_SKIP = {
    # Python
    "os", "sys", "json", "time", "re", "io", "uuid", "threading", "logging",
    "typing", "datetime", "pathlib", "collections", "itertools", "functools",
    "math", "random", "string", "hashlib", "hmac", "base64", "struct",
    "copy", "abc", "enum", "dataclasses", "contextlib", "traceback",
    "urllib", "http", "socket", "ssl", "email", "html", "xml", "csv",
    "sqlite3", "pickle", "shelve", "gzip", "zipfile", "tarfile",
    "subprocess", "shutil", "tempfile", "glob", "fnmatch", "stat",
    "platform", "argparse", "inspect", "ast", "dis", "importlib",
    "unittest", "doctest", "pdb", "profile", "timeit", "gc",
    # C/C++ standard headers
    "stdio.h", "stdlib.h", "string.h", "math.h", "time.h", "stdint.h",
    "stdbool.h", "stddef.h", "limits.h", "float.h", "ctype.h",
    "assert.h", "errno.h", "signal.h", "setjmp.h", "locale.h",
    "iostream", "vector", "string", "map", "set", "algorithm",
    "memory", "functional", "utility", "tuple", "array", "list",
    "queue", "stack", "deque", "bitset", "chrono", "thread", "mutex",
    "fstream", "sstream", "iomanip", "stdexcept", "exception", "typeinfo",
    # Node/browser built-ins
    "fs", "path", "os", "http", "https", "url", "crypto", "events",
    "stream", "buffer", "util", "net", "dns", "child_process", "cluster",
    "readline", "repl", "vm", "zlib", "assert", "timers", "console",
    "process", "module", "require",
}


@app.post("/scan-dependencies")
@limiter.limit("10/hour")
async def scan_dependencies_endpoint(
    request: Request,
    files: List[UploadFile] = File(...),
):
    """Parse imports from uploaded files and check OSV.dev for known CVEs."""
    try:
        files_content = process_file_content(files)
        if not files_content:
            return JSONResponse(status_code=400, content={"message": "No parseable files found."})
        
        ecosystem_map = parse_dependencies(files_content)
        logger.info(f"Detected ecosystems/packages: { {k: len(v) for k, v in ecosystem_map.items()} }")
        
        # Build OSV batch queries
        queries = []
        query_meta = []  # keep track of which pkg/ecosystem each query maps to
        
        osv_ecosystem_map = {"PyPI": "PyPI", "npm": "npm", "C/C++": ""}
        
        for ecosystem, pkgs in ecosystem_map.items():
            osv_eco = osv_ecosystem_map.get(ecosystem, "")
            for pkg in pkgs:
                if pkg.lower() in STD_LIB_SKIP:
                    continue
                if osv_eco:
                    queries.append({"package": {"name": pkg, "ecosystem": osv_eco}})
                else:
                    # C/C++ — search by package name only (no ecosystem)
                    queries.append({"package": {"name": pkg}})
                query_meta.append({"package": pkg, "ecosystem": ecosystem})
        
        osv_results = query_osv_batch(queries)
        
        # Build response
        vulnerable = []
        safe = []
        
        for i, result in enumerate(osv_results):
            if i >= len(query_meta):
                break
            meta = query_meta[i]
            advisories_raw = result.get("vulns", [])
            
            if advisories_raw:
                advisories = []
                for vuln in advisories_raw[:5]:  # cap at 5 per package
                    severity = "UNKNOWN"
                    # Try to extract severity from CVSS
                    for sev_entry in vuln.get("severity", []):
                        score_str = sev_entry.get("score", "")
                        if score_str:
                            try:
                                score = float(score_str)
                                if score >= 9.0: severity = "CRITICAL"
                                elif score >= 7.0: severity = "HIGH"
                                elif score >= 4.0: severity = "MEDIUM"
                                else: severity = "LOW"
                            except (ValueError, TypeError):
                                pass
                            break
                    # Fallback: check database-specific severity
                    if severity == "UNKNOWN":
                        db_sev = vuln.get("database_specific", {}).get("severity", "")
                        if db_sev:
                            severity = db_sev.upper()
                    
                    # Get fixed version from affected ranges
                    fixed_in = None
                    for affected in vuln.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_in = event["fixed"]
                                    break
                            if fixed_in:
                                break
                        if fixed_in:
                            break
                    
                    advisories.append({
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", "No summary available.")[:200],
                        "severity": severity,
                        "fixed_in": fixed_in,
                        "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}"
                    })
                
                vulnerable.append({
                    "package": meta["package"],
                    "ecosystem": meta["ecosystem"],
                    "advisory_count": len(advisories_raw),
                    "advisories": advisories
                })
            else:
                safe.append({"package": meta["package"], "ecosystem": meta["ecosystem"]})
        
        # Packages that were skipped (stdlib)
        skipped_count = sum(
            1 for eco_pkgs in ecosystem_map.values()
            for p in eco_pkgs if p.lower() in STD_LIB_SKIP
        )
        
        return JSONResponse(content={
            "vulnerable": vulnerable,
            "safe": safe,
            "skipped_stdlib_count": skipped_count,
            "total_checked": len(queries),
        })
    
    except Exception as e:
        logger.error(f"Dependency scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=(ENV_MODE == "development"))

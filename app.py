import json
import logging
import os
import time
import uuid
import secrets
import threading
import asyncio
import base64
import hashlib
import hmac
import re
import difflib
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File, WebSocket, WebSocketDisconnect, Response
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
ALLOW_CLIENT_API_KEYS = os.getenv("ALLOW_CLIENT_API_KEYS", "false").strip().lower() == "true"

# --- Auth Token Settings ---
_configured_auth_secret = os.getenv("AUTH_TOKEN_SECRET", "").strip()
if len(_configured_auth_secret) >= 32:
    AUTH_TOKEN_SECRET = _configured_auth_secret
else:
    AUTH_TOKEN_SECRET = secrets.token_urlsafe(48)
    logger.warning("AUTH_TOKEN_SECRET is not configured; using an ephemeral in-memory secret for this process.")
AUTH_TOKEN_TTL_SECONDS = int(os.getenv("AUTH_TOKEN_TTL_SECONDS", "28800"))
AUTH_COOKIE_NAME = "codeguard_auth_token"

# --- Input Validation Limits ---
MAX_USERNAME_LEN = 32
MAX_LOGIN_LEN = 128
MAX_EMAIL_LEN = 254
MAX_PASSWORD_LEN = 128
MAX_API_KEY_LEN = 256
MAX_PROVIDER_LEN = 20
MAX_PERSONA_LEN = 32
MAX_GITHUB_URL_LEN = 300
MAX_REPORT_ID_LEN = 64
MAX_SCAN_ID_LEN = 64

ALLOWED_PERSONAS = {"Student", "Professional"}
ALLOWED_PROVIDERS = {"auto", "groq", "openai", "gemini"}
SUPPORTED_CODE_EXTENSIONS = {"py", "cpp", "h", "c", "js", "ts", "tsx", "jsx", "tf", "tfvars"}

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CodeGuard AI Backend API", debug=DEBUG_MODE)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    # Allow production frontend URLs along with local development ones
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,https://codeguard-ai.up.railway.app"
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Content-Disposition"],
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
            "analyze-github": "POST /analyze-github - Analyze github repo url",
            "initialize-scan": "POST /initialize-scan - Start async GitHub scan job",
            "explore-engine": "GET /explore-engine - List available AI engines"
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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_auth_token(username: str) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + AUTH_TOKEN_TTL_SECONDS,
    }

    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)
    return f"{signing_input}.{encoded_signature}"


def verify_auth_token(token: str) -> Optional[str]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(
            AUTH_TOKEN_SECRET.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(_b64url_decode(encoded_signature), expected_signature):
            return None

        payload_raw = _b64url_decode(encoded_payload)
        payload = json.loads(payload_raw.decode("utf-8"))

        if int(payload.get("exp", 0)) < int(time.time()):
            return None

        username = payload.get("sub")
        if not isinstance(username, str) or not username.strip():
            return None

        return username.strip()
    except Exception:
        return None


def get_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        return token or None

    cookie_token = request.cookies.get(AUTH_COOKIE_NAME, "").strip()
    return cookie_token or None


def get_optional_authenticated_user(request: Request) -> Optional[str]:
    token = get_bearer_token(request)
    if not token:
        return None
    username = verify_auth_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username


def get_authenticated_user(request: Request) -> str:
    username = get_optional_authenticated_user(request)
    if not username:
        raise HTTPException(status_code=401, detail="Authentication required")
    return username


def _validate_text_field(raw: Optional[str], field_name: str, max_len: int, required: bool = False) -> str:
    value = (raw or "").strip()
    if required and not value:
        raise HTTPException(status_code=400, detail=f"{field_name} is required")
    if len(value) > max_len:
        raise HTTPException(status_code=400, detail=f"{field_name} is too long")
    return value


def _validate_optional_username(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    username = _validate_text_field(raw, "username", MAX_USERNAME_LEN, required=False)
    if not username:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters and contain only letters, numbers, ., _, or -")
    return username


def _validate_persona(raw: Optional[str]) -> str:
    persona = _validate_text_field(raw, "persona", MAX_PERSONA_LEN, required=True)
    if persona not in ALLOWED_PERSONAS:
        raise HTTPException(status_code=400, detail=f"Invalid persona. Allowed values: {', '.join(sorted(ALLOWED_PERSONAS))}")
    return persona


def _validate_provider(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    provider = _validate_text_field(raw, "provider", MAX_PROVIDER_LEN, required=False).lower()
    if not provider:
        return None
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid provider. Allowed values: {', '.join(sorted(ALLOWED_PROVIDERS))}")
    return provider


def _validate_api_key(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    api_key = _validate_text_field(raw, "api_key", MAX_API_KEY_LEN, required=False)
    if not api_key:
        return None
    if any(ch.isspace() for ch in api_key):
        raise HTTPException(status_code=400, detail="API key must not contain whitespace")
    return api_key


def _validate_github_url(raw: str) -> str:
    url = _validate_text_field(raw, "github_url", MAX_GITHUB_URL_LEN, required=True)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="GitHub URL must start with http:// or https://")
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise HTTPException(status_code=400, detail="Only github.com URLs are allowed")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="GitHub URL must include owner and repository")
    return url


def _validate_uuid_field(raw: str, field_name: str, max_len: int) -> str:
    value = _validate_text_field(raw, field_name, max_len, required=True)
    try:
        parsed_uuid = uuid.UUID(value)
        return str(parsed_uuid)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name} format")


def _safe_diff_filename(file_name: str) -> str:
    cleaned = (file_name or "").replace("\r", "").replace("\n", "").replace("\x00", "")
    cleaned = cleaned.replace("\\", "/").split("/")[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", cleaned)
    return cleaned or "file"


def _set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=AUTH_TOKEN_TTL_SECONDS,
        expires=AUTH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=not DEBUG_MODE,
        samesite="lax",
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key=AUTH_COOKIE_NAME, path="/")

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    login: str  # can be email or username
    password: str


class InitializeScanRequest(BaseModel):
    github_url: str
    persona: str = "Student"
    provider: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None

@app.post("/api/register")
@limiter.limit("10/minute")
async def register(request: Request, req: RegisterRequest):
    username = _validate_text_field(req.username, "username", MAX_USERNAME_LEN, required=True)
    email = _validate_text_field(req.email, "email", MAX_EMAIL_LEN, required=True).lower()
    password = _validate_text_field(req.password, "password", MAX_PASSWORD_LEN, required=True)

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters and contain only letters, numbers, ., _, or -")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # check if user exists
    c.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE OR email = ?", (username, email))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # hash password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    c.execute("""
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
    """, (username, email, hashed.decode('utf-8')))
    conn.commit()
    conn.close()
    
    return {"message": "User registered successfully"}

@app.post("/api/login")
@limiter.limit("20/minute")
async def login(request: Request, req: LoginRequest, response: Response):
    login_value = _validate_text_field(req.login, "login", MAX_LOGIN_LEN, required=True)
    password = _validate_text_field(req.password, "password", MAX_PASSWORD_LEN, required=True)

    if not login_value or not password:
        raise HTTPException(status_code=400, detail="Login and password are required")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE OR email = ?", (login_value, login_value.lower()))
    user = c.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    user_id, username, stored_hash = user
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_auth_token(username)
    _set_auth_cookie(response, token)
        
    return {
        "message": "Login successful",
        "token": token,
        "expires_in": AUTH_TOKEN_TTL_SECONDS,
        "user": {
            "id": user_id,
            "username": username
        }
    }

# In-memory storage for reports (so GET /export-pdf works statelessly for the client)
REPORT_CACHE: Dict[str, Dict[str, Any]] = {}
HISTORY_FILE = "scan_history.json"
history_lock = threading.Lock()
scan_task_lock = threading.Lock()

# Async scan task storage and websocket subscriptions.
SCAN_TASKS: Dict[str, Dict[str, Any]] = {}
SCAN_SUBSCRIBERS: Dict[str, List[WebSocket]] = {}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def is_supported_source_file(filename: str) -> bool:
    if not filename:
        return False
    normalized = filename.strip().lower().split("/")[-1]
    if normalized in {"dockerfile", "containerfile"}:
        return True
    if "." not in normalized:
        return False
    ext = normalized.rsplit(".", 1)[-1]
    return ext in SUPPORTED_CODE_EXTENSIONS


def sanitize_scan_finding(finding: Dict[str, Any], filename: str) -> Dict[str, Any]:
    issue_description = str(finding.get("issue_description", "")).strip()
    if not issue_description:
        issue_description = "[LOW] Issue reported without description"
    elif not issue_description.startswith("["):
        issue_description = f"[LOW] {issue_description}"

    return {
        "file_name": str(finding.get("file_name") or filename),
        "issue_description": issue_description,
        "root_problem": str(finding.get("root_problem", "")).strip(),
        "suggested_solution": str(finding.get("suggested_solution", "")).strip(),
        "suggested_fix": str(finding.get("suggested_fix", "")).strip() or "Apply secure validation, output encoding, and least-privilege controls.",
        "source_code": str(finding.get("source_code", "")).strip(),
        "fixed_code": str(finding.get("fixed_code", "")).strip(),
    }


def build_static_issue(
    filename: str,
    severity: str,
    title: str,
    root_problem: str,
    suggested_solution: str,
    suggested_fix: str,
    source_code: str = "",
    fixed_code: str = "",
) -> Dict[str, Any]:
    return {
        "file_name": filename,
        "issue_description": f"[{severity}] {title}",
        "root_problem": root_problem,
        "suggested_solution": suggested_solution,
        "suggested_fix": suggested_fix,
        "source_code": source_code,
        "fixed_code": fixed_code,
        "detected_by": "sast",
    }


def run_lightweight_sast(filename: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lowered = content.lower()

    # Hardcoded secret patterns.
    secret_patterns = [
        r"(?i)api[_-]?key\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        r"(?i)secret\s*=\s*[\"'][^\"']{12,}[\"']",
        r"(?i)password\s*=\s*[\"'][^\"']{8,}[\"']",
        r"(?i)token\s*=\s*[\"'][A-Za-z0-9_\-\.]{16,}[\"']",
    ]
    for pattern in secret_patterns:
        match = re.search(pattern, content)
        if match:
            findings.append(
                build_static_issue(
                    filename=filename,
                    severity="HIGH",
                    title="Hardcoded secret detected",
                    root_problem="Sensitive credential material appears directly in source code.",
                    suggested_solution="Move secrets to environment variables or a managed secret store.",
                    suggested_fix="Replace hardcoded credential literals with runtime secret retrieval and rotate exposed keys.",
                    source_code=match.group(0),
                )
            )
            break

    # Python eval/exec misuse.
    if filename.lower().endswith(".py") and re.search(r"\b(eval|exec)\s*\(", content):
        findings.append(
            build_static_issue(
                filename=filename,
                severity="HIGH",
                title="Dynamic code execution risk",
                root_problem="Use of eval/exec can execute untrusted input and lead to remote code execution.",
                suggested_solution="Use safe parsers and explicit mappings instead of dynamic execution.",
                suggested_fix="Replace eval/exec with controlled dispatch tables or ast.literal_eval for trusted literal parsing.",
            )
        )

    # SQL injection heuristics.
    # Split the regex string to prevent the SAST scanner from aggressively flagging its own rules
    sql_keywords = r"(?i)(s" + r"elect|i" + r"nsert|u" + r"pdate|d" + r"elete)"
    if re.search(sql_keywords + r".*(\+|%\s*s|\.format\()", content):
        findings.append(
            build_static_issue(
                filename=filename,
                severity="HIGH",
                title="Possible SQL injection",
                root_problem="SQL query string interpolation may allow attacker-controlled input to alter queries.",
                suggested_solution="Use parameterized queries or ORM parameter binding for all dynamic values.",
                suggested_fix="Refactor query construction to parameterized placeholders and pass values separately via driver APIs.",
            )
        )

    # JavaScript/TypeScript dangerous sinks.
    if any(filename.lower().endswith(ext) for ext in (".js", ".ts", ".jsx", ".tsx")):
        if "dangerouslysetinnerhtml" in lowered or "innerhtml =" in lowered:
            findings.append(
                build_static_issue(
                    filename=filename,
                    severity="MEDIUM",
                    title="Potential cross-site scripting sink",
                    root_problem="Direct HTML injection sink is present and may render unsanitized data.",
                    suggested_solution="Use safe templating and sanitize all untrusted HTML before rendering.",
                    suggested_fix="Avoid direct HTML sinks; prefer escaped rendering and strict allowlist-based sanitization.",
                )
            )

    # IaC guardrails.
    if filename.lower().endswith("dockerfile") or filename.lower().endswith("containerfile"):
        if re.search(r"(?im)^\s*user\s+root", content):
            findings.append(
                build_static_issue(
                    filename=filename,
                    severity="MEDIUM",
                    title="Container runs as root",
                    root_problem="Running containers as root increases impact of container breakout and lateral movement.",
                    suggested_solution="Use a non-root runtime user and drop unnecessary Linux capabilities.",
                    suggested_fix="Create and switch to a dedicated low-privilege user before entrypoint execution.",
                )
            )
    if filename.lower().endswith(".tf"):
        if re.search(r"0\.0\.0\.0/0", content):
            findings.append(
                build_static_issue(
                    filename=filename,
                    severity="HIGH",
                    title="Overly permissive network exposure in Terraform",
                    root_problem="Ingress/egress open to the public internet broadens attack surface.",
                    suggested_solution="Restrict CIDR ranges to trusted networks and enforce least privilege network policy.",
                    suggested_fix="Replace 0.0.0.0/0 with explicit trusted CIDR blocks and segment exposed services.",
                )
            )

    deduped: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = f"{finding.get('file_name','')}|{finding.get('issue_description','')}"
        deduped[key] = finding
    return list(deduped.values())


def merge_hybrid_findings(ai_result: Dict[str, Any], sast_findings: List[Dict[str, Any]], filename: str) -> Dict[str, Any]:
    ai_findings = ai_result.get("findings", []) if isinstance(ai_result.get("findings", []), list) else []
    normalized_ai = [sanitize_scan_finding(f, filename) for f in ai_findings if isinstance(f, dict)]

    merged: List[Dict[str, Any]] = []
    seen = set()

    for finding in normalized_ai + [sanitize_scan_finding(f, filename) for f in sast_findings if isinstance(f, dict)]:
        key = (finding.get("file_name", ""), finding.get("issue_description", ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(finding)

    merged = sort_findings_by_severity(merged)
    merged_stats = build_stats_from_findings(merged)

    merged_result = dict(ai_result)
    merged_result["findings"] = merged
    merged_result["stats"] = merged_stats
    merged_result["status"] = "VULNERABLE" if merged else "SAFE"
    merged_result["scanned_file_name"] = filename
    return merged_result


def compute_security_score(stats: Dict[str, Any], total_files: int, overall_status: str) -> Dict[str, Any]:
    high = int(stats.get("High", 0))
    medium = int(stats.get("Medium", 0))
    low = int(stats.get("Low", 0))
    error_penalty = 15 if str(overall_status).upper() == "ERROR" else 0

    score = 100 - (high * 20) - (medium * 10) - (low * 4) - error_penalty
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "total_files": total_files,
        "weights": {
            "high": 20,
            "medium": 10,
            "low": 4,
            "error": 15,
        },
        "rationale": "Score starts at 100 and subtracts weighted penalties for unresolved findings.",
    }


def _set_scan_task(scan_id: str, **kwargs: Any) -> Dict[str, Any]:
    with scan_task_lock:
        current = SCAN_TASKS.get(scan_id, {})
        current.update(kwargs)
        current["updated_at"] = _utc_timestamp()
        SCAN_TASKS[scan_id] = current
        return dict(current)


def get_scan_task(scan_id: str) -> Optional[Dict[str, Any]]:
    with scan_task_lock:
        task = SCAN_TASKS.get(scan_id)
        return dict(task) if task else None


async def notify_scan_subscribers(scan_id: str) -> None:
    payload = get_scan_task(scan_id)
    if not payload:
        return
    subscribers = SCAN_SUBSCRIBERS.get(scan_id, [])
    if not subscribers:
        return

    alive: List[WebSocket] = []
    for ws in subscribers:
        try:
            await ws.send_json(payload)
            alive.append(ws)
        except Exception as exc:
            logger.debug("Dropping stale scan subscriber for %s: %s", scan_id, exc)
    SCAN_SUBSCRIBERS[scan_id] = alive


async def register_scan_socket(scan_id: str, websocket: WebSocket) -> None:
    await websocket.accept()
    subscribers = SCAN_SUBSCRIBERS.setdefault(scan_id, [])
    subscribers.append(websocket)
    await notify_scan_subscribers(scan_id)


def unregister_scan_socket(scan_id: str, websocket: WebSocket) -> None:
    subscribers = SCAN_SUBSCRIBERS.get(scan_id, [])
    SCAN_SUBSCRIBERS[scan_id] = [ws for ws in subscribers if ws is not websocket]


class AsyncScanResponse(BaseModel):
    scan_id: str
    status: str
    ws_path: str


class ApplyFixRequest(BaseModel):
    file_name: str
    source_code: str
    fixed_code: str


def build_fix_preview_diff(file_name: str, source_code: str, fixed_code: str) -> str:
    source_lines = source_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)
    safe_name = _safe_diff_filename(file_name)
    diff_lines = difflib.unified_diff(
        source_lines,
        fixed_lines,
        fromfile=f"a/{safe_name}",
        tofile=f"b/{safe_name}",
        lineterm="",
    )
    return "\n".join(diff_lines)


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


MAX_ZIP_ENTRIES = 50


def _is_safe_zip_member_name(member_name: str) -> bool:
    normalized = (member_name or "").replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or "\x00" in normalized:
        return False
    if normalized in {".", ".."}:
        return False
    if normalized.startswith("../") or "/../" in normalized or normalized.endswith("/.."): 
        return False
    return True


def _extract_supported_files_from_zip_bytes(archive_name: str, content_bytes: bytes) -> List[Dict[str, str]]:
    extracted_files: List[Dict[str, str]] = []
    total_uncompressed_size = 0

    with zipfile.ZipFile(io.BytesIO(content_bytes)) as archive:
        for index, entry in enumerate(archive.infolist()):
            if index >= MAX_ZIP_ENTRIES or len(extracted_files) >= MAX_FILES_PER_SCAN:
                break
            if entry.is_dir():
                continue

            entry_name = entry.filename.replace("\\", "/").lstrip("./")
            if not _is_safe_zip_member_name(entry_name):
                continue
            if not is_supported_source_file(entry_name):
                continue
            if entry.file_size > MAX_FILE_SIZE:
                logger.warning("Skipping oversized archive member %s from %s (%s bytes)", entry_name, archive_name, entry.file_size)
                continue

            projected_total = total_uncompressed_size + entry.file_size
            if projected_total > MAX_TOTAL_SCAN_SIZE:
                logger.warning("Archive %s exceeds total uncompressed size budget; stopping extraction.", archive_name)
                break

            with archive.open(entry) as internal_file:
                file_bytes = internal_file.read(MAX_FILE_SIZE + 1)
                if len(file_bytes) > MAX_FILE_SIZE:
                    logger.warning("Skipping archive member %s from %s after read-size validation.", entry_name, archive_name)
                    continue

                extracted_files.append({
                    "name": entry_name,
                    "content": file_bytes.decode("utf-8", errors="ignore"),
                })
                total_uncompressed_size += len(file_bytes)

    return extracted_files

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


def build_error_scan_response(message: str, report_id: Optional[str] = None) -> JSONResponse:
    """Return a structured scan response so the frontend can render failures inline."""
    safe_message = redact_sensitive_text(message)
    payload = {
        "report_id": report_id or str(uuid.uuid4()),
        "status": "ERROR",
        "stats": {"High": 0, "Medium": 0, "Low": 0},
        "findings": [{
            "file_name": "unknown",
            "issue_description": f"Analysis Error: {safe_message}",
            "suggested_fix": "Retry the scan or verify the configured AI provider and local services.",
        }],
        "improvement_suggestions": [],
    }
    return JSONResponse(content=payload)


def redact_sensitive_text(text: Any) -> str:
    raw = str(text or "")

    # Mask common provider key patterns if they appear in exception strings.
    redacted = re.sub(r"gsk_[A-Za-z0-9_\-]{8,}", "gsk_[REDACTED]", raw)
    redacted = re.sub(r"sk-[A-Za-z0-9]{8,}", "sk-[REDACTED]", redacted)
    redacted = re.sub(r"AIza[0-9A-Za-z_\-]{8,}", "AIza[REDACTED]", redacted)
    redacted = re.sub(r"Bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted

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
        safe_error = redact_sensitive_text(e)
        logger.error(f"OpenAI API Error: {safe_error}")
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"OpenAI Error: {safe_error}", 
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
        safe_error = redact_sensitive_text(e)
        logger.error(f"Gemini API Error: {safe_error}")
        return json.dumps({
            "status": "ERROR", 
            "stats": {"High": 0, "Medium": 0, "Low": 0}, 
            "findings": [{
                "file_name": "unknown", 
                "issue_description": f"Gemini Error: {safe_error}", 
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
        safe_error = redact_sensitive_text(e)
        logger.error(f"Groq API Error (strict JSON mode): {safe_error}")

        # Groq may reject a near-valid response in strict JSON mode.
        # Retry once without response_format and force plain JSON text output.
        try:
            client = groq.Groq(api_key=api_key)
            retry_completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            system_prompt
                            + "\n\nIMPORTANT: Return only one valid JSON object."
                            + " Do not include markdown, explanations, or trailing text."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                max_tokens=1400,
            )
            fallback_text = retry_completion.choices[0].message.content or ""
            if fallback_text.strip():
                return fallback_text
        except Exception as retry_error:
            logger.error(f"Groq retry without strict JSON mode failed: {redact_sensitive_text(retry_error)}")

        return json.dumps({
            "status": "ERROR",
            "stats": {"High": 0, "Medium": 0, "Low": 0},
            "findings": [{
                "file_name": "unknown",
                "issue_description": f"Groq Error: {safe_error}",
                "suggested_fix": "Check API key, prompt size, or rate limits."
            }]
        })


def extract_first_json_object(raw: str) -> Optional[str]:
    """Extract first balanced JSON object from arbitrary text."""
    if not raw:
        return None

    text = raw.strip()
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]

    return None


def _try_parse_json_relaxed(text: str) -> Optional[Dict[str, Any]]:
    """Parse JSON with lightweight repairs for common LLM formatting mistakes."""
    if not text:
        return None

    candidates = [text.strip()]

    extracted = extract_first_json_object(text)
    if extracted:
        candidates.append(extracted)

    for candidate in candidates:
        parsed: Optional[Dict[str, Any]] = None
        try:
            loaded = json.loads(candidate)
            if isinstance(loaded, dict):
                parsed = loaded
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Direct JSON parse failed during relaxed parse: %s", exc)
        if parsed is not None:
            return parsed

        # Repair pass: remove trailing commas before closing braces/brackets.
        repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
        repaired_parsed: Optional[Dict[str, Any]] = None
        try:
            repaired_loaded = json.loads(repaired)
            if isinstance(repaired_loaded, dict):
                repaired_parsed = repaired_loaded
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Repaired JSON parse failed during relaxed parse: %s", exc)
        if repaired_parsed is not None:
            return repaired_parsed

    return None

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
            parsed = _try_parse_json_relaxed(json_str)
        else:
            parsed = _try_parse_json_relaxed(ai_text)

        if not parsed:
            raise ValueError("Could not parse valid JSON from model output")
        
        if "findings" in parsed:
            parsed["findings"] = sort_findings_by_severity(parsed["findings"])
            parsed["stats"] = build_stats_from_findings(parsed["findings"])
        else:
            parsed["findings"] = []
            parsed["stats"] = {"High": 0, "Medium": 0, "Low": 0}

        if "overall_code_review" not in parsed or not isinstance(parsed.get("overall_code_review"), dict):
            parsed["overall_code_review"] = {
                "summary": "No professional code review was returned by the model.",
                "strengths": [],
                "key_risks": [],
                "maintainability_assessment": "Not assessed.",
                "test_recommendations": [],
                "priority_actions": []
            }

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
            }],
            "overall_code_review": {
                "summary": "Model output could not be parsed into valid JSON; professional review is incomplete.",
                "strengths": [],
                "key_risks": ["Response parsing failed, so the review quality is degraded."],
                "maintainability_assessment": "Not fully assessed due to model output format issues.",
                "test_recommendations": ["Re-run scan and validate model/provider response formatting."],
                "priority_actions": ["Re-run the scan with a stable provider configuration."]
            }
        }


def normalize_provider_choice(provider: Optional[str]) -> str:
    normalized = (provider or "").strip().lower()
    if normalized in {"groq", "openai", "gemini", "auto"}:
        return normalized
    return "auto"


def build_provider_error_json(issue_description: str, suggested_fix: str) -> str:
    return json.dumps({
        "status": "ERROR",
        "stats": {"High": 0, "Medium": 0, "Low": 0},
        "findings": [{
            "file_name": "unknown",
            "issue_description": issue_description,
            "suggested_fix": suggested_fix,
        }],
    })


def call_provider_with_json_prompt(
    prompt: str,
    system_prompt: str,
    api_key: str,
    provider: Optional[str],
    temperature: float = 0.1
) -> str:
    chosen_provider = normalize_provider_choice(provider)
    key = (api_key or "").strip()

    if chosen_provider == "groq":
        if not key:
            return build_provider_error_json(
                "Provider Error: Missing API key for Groq.",
                "Provide a Groq API key (starts with gsk_) or use provider=auto with a configured server default key.",
            )
        return call_groq(prompt, system_prompt, key, temperature)
    if chosen_provider == "openai":
        if not key:
            return build_provider_error_json(
                "Provider Error: Missing API key for OpenAI.",
                "Provide an OpenAI API key (starts with sk-), or select auto with a supported key.",
            )
        return call_openai(prompt, system_prompt, key)
    if chosen_provider == "gemini":
        if not key:
            return build_provider_error_json(
                "Provider Error: Missing API key for Gemini.",
                "Provide a Gemini API key (starts with AIzaSy), or select auto with a supported key.",
            )
        return call_gemini(prompt, system_prompt, key)

    if key.startswith("gsk_"):
        return call_groq(prompt, system_prompt, key, temperature)
    if key.startswith("sk-"):
        return call_openai(prompt, system_prompt, key)
    if key.startswith("AIzaSy"):
        return call_gemini(prompt, system_prompt, key)
    if not key and DEFAULT_GROQ_API_KEY:
        return call_groq(prompt, system_prompt, DEFAULT_GROQ_API_KEY, temperature)

    if key:
        return build_provider_error_json(
            "Provider Error: Unsupported API key format for auto provider.",
            "Use one of: gsk_ (Groq), sk- (OpenAI), or AIzaSy (Gemini), or select an explicit provider.",
        )

    return build_provider_error_json(
        "Provider Error: No API key available for analysis.",
        "Provide an API key or configure DEFAULT_GROQ_API_KEY on the backend environment.",
    )


def build_fallback_file_review(file_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    finding_count = len(file_findings)
    high = sum(1 for f in file_findings if extract_severity(f.get("issue_description", "")) == "High")
    medium = sum(1 for f in file_findings if extract_severity(f.get("issue_description", "")) == "Medium")
    low = sum(1 for f in file_findings if extract_severity(f.get("issue_description", "")) == "Low")

    if finding_count == 0:
        return {
            "summary": "No vulnerabilities were detected in this file during the current scan.",
            "strengths": [
                "No explicit security findings were reported by the static AI scan.",
                "Code appears to avoid obvious high-risk anti-patterns in this pass."
            ],
            "key_risks": [
                "Absence of findings does not guarantee exploit resistance.",
                "Runtime behavior and edge cases still require testing."
            ],
            "maintainability_assessment": "Maintainability risk appears low from a security perspective in this scan.",
            "test_recommendations": [
                "Add negative-path tests for malformed inputs.",
                "Run dependency and runtime security checks in CI."
            ],
            "priority_actions": [
                "Keep regression tests for auth, validation, and error handling up to date.",
                "Re-run this scan after major refactors or dependency upgrades."
            ]
        }

    return {
        "summary": (
            f"This file has {finding_count} issue(s): {high} high, {medium} medium, and {low} low severity. "
            "Security hardening should prioritize high-impact vulnerabilities first."
        ),
        "strengths": [
            "The scan provided concrete remediation guidance for identified issues.",
            "Findings are categorized by severity for prioritization."
        ],
        "key_risks": [
            "Unresolved findings can lead to security exposure in production.",
            "Compounded medium and low findings may still become exploitable in chained attacks."
        ],
        "maintainability_assessment": "Maintainability is currently affected by the number of unresolved security findings.",
        "test_recommendations": [
            "Introduce focused tests for each vulnerability path and remediation.",
            "Add regression tests to prevent reintroduction of fixed issues."
        ],
        "priority_actions": [
            "Fix all high-severity issues before release.",
            "Schedule remediation for medium and low issues with owners and due dates."
        ]
    }


def review_has_substance(review: Dict[str, Any]) -> bool:
    if not isinstance(review, dict):
        return False

    summary = str(review.get("summary", "")).strip().lower()
    if not summary or "no professional code review was returned by the model" in summary:
        return False

    list_fields = ["strengths", "key_risks", "test_recommendations", "priority_actions"]
    list_content_count = 0
    for field in list_fields:
        value = review.get(field, [])
        if isinstance(value, list):
            list_content_count += len([v for v in value if str(v).strip()])

    return list_content_count > 0


def generate_file_overall_review(
    filename: str,
    content: str,
    findings: List[Dict[str, Any]],
    persona: str,
    api_key: str,
    provider: Optional[str]
) -> Dict[str, Any]:
    condensed_findings = []
    for finding in findings[:10]:
        condensed_findings.append({
            "issue_description": finding.get("issue_description", ""),
            "root_problem": finding.get("root_problem", ""),
            "suggested_solution": finding.get("suggested_solution", ""),
            "suggested_fix": finding.get("suggested_fix", "")
        })

    system_prompt = (
        "You are a Principal Software Reviewer and Application Security Architect. "
        "Return ONLY one valid JSON object with this exact schema:\n"
        "{\n"
        "  \"summary\": \"string\",\n"
        "  \"strengths\": [\"item 1\", \"item 2\"],\n"
        "  \"key_risks\": [\"item 1\", \"item 2\"],\n"
        "  \"maintainability_assessment\": \"string\",\n"
        "  \"test_recommendations\": [\"item 1\", \"item 2\"],\n"
        "  \"priority_actions\": [\"item 1\", \"item 2\"]\n"
        "}\n"
        "Review the file itself, not only vulnerabilities. Be concrete and professional."
    )

    prompt = (
        f"Persona: {persona}\n"
        f"File name: {filename}\n"
        "Generate a professional overall code review for this specific file.\n"
        "Include architecture/readability observations, security posture, maintainability, and test strategy.\n"
        "Do not output placeholders; provide actionable details.\n\n"
        f"Findings summary JSON:\n{json.dumps(condensed_findings, ensure_ascii=True)}\n\n"
        f"File content:\n---\n{content[:12000]}\n---\n"
    )

    try:
        raw = call_provider_with_json_prompt(prompt, system_prompt, api_key, provider, temperature=0.1)
        parsed = _try_parse_json_relaxed(raw)
        if isinstance(parsed, dict):
            parsed.setdefault("summary", "Professional review generated from file content and findings.")
            parsed.setdefault("strengths", [])
            parsed.setdefault("key_risks", [])
            parsed.setdefault("maintainability_assessment", "Maintainability assessed based on file structure and risk profile.")
            parsed.setdefault("test_recommendations", [])
            parsed.setdefault("priority_actions", [])
            return parsed
    except Exception as e:
        logger.error(f"Failed to generate dedicated file review for {filename}: {e}")

    return build_fallback_file_review(findings)


def generate_executive_vulnerability_summary(
    findings: List[Dict[str, Any]],
    persona: str,
    api_key: str,
    provider: Optional[str]
) -> Dict[str, Any]:
    def map_issue_to_standards(issue_text: str) -> Dict[str, List[str]]:
        text = (issue_text or "").lower()

        # Lightweight keyword mapping to maintain useful output even when model output is partial.
        rules = [
            (("sql injection", "sqli"), (["CWE-89"], ["A03:2021 - Injection"])),
            (("xss", "cross-site scripting"), (["CWE-79"], ["A03:2021 - Injection"])),
            (("path traversal", "directory traversal"), (["CWE-22"], ["A01:2021 - Broken Access Control"])),
            (("hardcoded", "api key", "secret", "credential"), (["CWE-798"], ["A02:2021 - Cryptographic Failures"])),
            (("deserialization",), (["CWE-502"], ["A08:2021 - Software and Data Integrity Failures"])),
            (("auth", "authorization", "access control"), (["CWE-284"], ["A01:2021 - Broken Access Control"])),
            (("buffer overflow", "out-of-bounds"), (["CWE-120"], ["A05:2021 - Security Misconfiguration"])),
            (("ssrf",), (["CWE-918"], ["A10:2021 - Server-Side Request Forgery"])),
            (("race condition",), (["CWE-362"], ["A04:2021 - Insecure Design"])),
            (("xxe", "xml external entity"), (["CWE-611"], ["A05:2021 - Security Misconfiguration"])),
        ]

        cwe_ids: List[str] = []
        owasp: List[str] = []
        for keys, (cwe_list, owasp_list) in rules:
            if any(k in text for k in keys):
                cwe_ids.extend(cwe_list)
                owasp.extend(owasp_list)

        if not cwe_ids:
            cwe_ids = ["CWE-Other"]
        if not owasp:
            owasp = ["A04:2021 - Insecure Design"]

        return {
            "cwe_ids": sorted(set(cwe_ids)),
            "owasp_categories": sorted(set(owasp))
        }

    if not findings:
        return {
            "overall_assessment": "No vulnerabilities were detected in this scan.",
            "most_important_findings": [],
            "immediate_next_steps": [
                "Maintain secure coding and dependency hygiene.",
                "Continue periodic scans and add targeted security tests."
            ]
        }

    sorted_findings = sort_findings_by_severity(findings)
    top_findings = sorted_findings[:20]
    condensed_findings = []
    for f in top_findings:
        condensed_findings.append({
            "file_name": f.get("file_name", "unknown"),
            "severity": extract_severity(f.get("issue_description", "")),
            "issue_description": f.get("issue_description", ""),
            "root_problem": f.get("root_problem", ""),
            "suggested_solution": f.get("suggested_solution", ""),
            "suggested_fix": f.get("suggested_fix", "")
        })

    system_prompt = (
        "You are a Principal Application Security Reviewer. "
        "Return ONLY valid JSON with this exact schema:\n"
        "{\n"
        "  \"overall_assessment\": \"string\",\n"
        "  \"most_important_findings\": [{\n"
        "    \"title\": \"string\",\n"
        "    \"severity\": \"High|Medium|Low\",\n"
        "    \"cwe_ids\": [\"CWE-79\"],\n"
        "    \"owasp_categories\": [\"A03:2021 - Injection\"],\n"
        "    \"affected_files\": [\"file\"],\n"
        "    \"why_it_matters\": \"detailed explanation\",\n"
        "    \"attack_scenario\": \"realistic exploitation path\",\n"
        "    \"business_impact\": \"impact on confidentiality/integrity/availability and operations\",\n"
        "    \"recommended_actions\": [\"action 1\", \"action 2\", \"action 3\"]\n"
        "  }],\n"
        "  \"immediate_next_steps\": [\"step 1\", \"step 2\", \"step 3\"]\n"
        "}\n"
        "Prioritize depth, precision, and professional enterprise tone."
    )

    prompt = (
        f"Persona: {persona}\n"
        "Use the findings below and produce a detailed executive summary focused on the most important vulnerabilities.\n"
        "Focus on concrete risk impact and practical remediation sequencing.\n\n"
        "For each important finding, map to relevant CWE IDs and OWASP Top 10 (2021) categories.\n"
        "Keep statements evidence-based and concise enough for leadership review.\n\n"
        f"Findings JSON:\n{json.dumps(condensed_findings, ensure_ascii=True)}\n"
    )

    try:
        raw = call_provider_with_json_prompt(prompt, system_prompt, api_key, provider, temperature=0.1)
        parsed = _try_parse_json_relaxed(raw)
        if isinstance(parsed, dict):
            if "most_important_findings" not in parsed or not isinstance(parsed.get("most_important_findings"), list):
                parsed["most_important_findings"] = []
            if "immediate_next_steps" not in parsed or not isinstance(parsed.get("immediate_next_steps"), list):
                parsed["immediate_next_steps"] = []

            for item in parsed["most_important_findings"]:
                if not isinstance(item, dict):
                    continue
                mapped = map_issue_to_standards(item.get("title", ""))
                if "cwe_ids" not in item or not isinstance(item.get("cwe_ids"), list) or not item.get("cwe_ids"):
                    item["cwe_ids"] = mapped["cwe_ids"]
                if "owasp_categories" not in item or not isinstance(item.get("owasp_categories"), list) or not item.get("owasp_categories"):
                    item["owasp_categories"] = mapped["owasp_categories"]
                item.setdefault(
                    "business_impact",
                    "This weakness may impact confidentiality, integrity, or availability if exploited in production."
                )

            parsed.setdefault("overall_assessment", "Executive summary generated from scan findings.")
            return parsed
    except Exception as e:
        logger.error(f"Failed generating executive summary with AI provider: {e}")

    fallback_items = []
    for finding in top_findings[:8]:
        severity = extract_severity(finding.get("issue_description", ""))
        mapped = map_issue_to_standards(finding.get("issue_description", ""))
        fallback_items.append({
            "title": finding.get("issue_description", "Untitled finding"),
            "severity": severity,
            "cwe_ids": mapped["cwe_ids"],
            "owasp_categories": mapped["owasp_categories"],
            "affected_files": [finding.get("file_name", "unknown")],
            "why_it_matters": finding.get("root_problem") or "This issue increases attack surface and risk exposure.",
            "attack_scenario": "An attacker could abuse this weakness to compromise confidentiality, integrity, or availability.",
            "business_impact": "Potential service disruption, data exposure, or trust and compliance impact depending on exploitability.",
            "recommended_actions": [
                finding.get("suggested_solution") or "Implement secure coding remediation and validation controls.",
                finding.get("suggested_fix") or "Apply the proposed patch and verify behavior with tests.",
                "Add regression security tests to prevent recurrence."
            ]
        })

    return {
        "overall_assessment": "Fallback executive summary generated from structured findings due to provider output constraints.",
        "most_important_findings": fallback_items,
        "immediate_next_steps": [
            "Remediate high-severity issues first and verify with tests.",
            "Create owners and deadlines for each remaining finding.",
            "Re-run full scan after fixes and compare results."
        ]
    }

def analyze_code_logic(filename: str, content: str, api_key: str, persona: str, provider: str = None):
    if "Student" in persona:
        system_rules = (
            "You are a helpful Security Tutor for students. Your goal is to encourage learning and growth. "
            "You MUST respond with ONLY valid JSON (no markdown, no extra text) following this exact schema:\n"
            "{\n"
            "  \"status\": \"SAFE\" or \"VULNERABLE\",\n"
            "  \"stats\": {\"High\": 0, \"Medium\": 0, \"Low\": 0},\n"
            "  \"findings\": [{\n"
            "    \"file_name\": \"filename\",\n"
            "    \"issue_description\": \"issue title with [SEVERITY]\",\n"
            "    \"root_problem\": \"one-sentence explanation of the cause\",\n"
            "    \"suggested_solution\": \"high-level fixing approach\",\n"
            "    \"suggested_fix\": \"detailed code correction or remediation steps\",\n"
            "    \"source_code\": \"problematic snippet\",\n"
            "    \"fixed_code\": \"corrected snippet\"\n"
            "  }],\n"
            "  \"overall_code_review\": {\n"
            "    \"summary\": \"professional review summary\",\n"
            "    \"strengths\": [\"strength 1\", \"strength 2\"],\n"
            "    \"key_risks\": [\"risk 1\", \"risk 2\"],\n"
            "    \"maintainability_assessment\": \"maintainability and code quality assessment\",\n"
            "    \"test_recommendations\": [\"test recommendation 1\", \"test recommendation 2\"],\n"
            "    \"priority_actions\": [\"priority 1\", \"priority 2\"]\n"
            "  },\n"
            "  \"improvement_suggestions\": [\"suggestion1\", \"suggestion2\", \"suggestion3\"]\n"
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
            "  \"status\": \"SAFE\" or \"VULNERABLE\",\n"
            "  \"stats\": {\"High\": 0, \"Medium\": 0, \"Low\": 0},\n"
            "  \"findings\": [{\n"
            "    \"file_name\": \"filename\",\n"
            "    \"issue_description\": \"issue title with [SEVERITY]\",\n"
            "    \"root_problem\": \"one-sentence explanation of the cause\",\n"
            "    \"suggested_solution\": \"high-level fixing approach\",\n"
            "    \"suggested_fix\": \"detailed code correction or remediation steps\",\n"
            "    \"source_code\": \"problematic snippet\",\n"
            "    \"fixed_code\": \"corrected snippet\"\n"
            "  }],\n"
            "  \"overall_code_review\": {\n"
            "    \"summary\": \"professional review summary\",\n"
            "    \"strengths\": [\"strength 1\", \"strength 2\"],\n"
            "    \"key_risks\": [\"risk 1\", \"risk 2\"],\n"
            "    \"maintainability_assessment\": \"maintainability and code quality assessment\",\n"
            "    \"test_recommendations\": [\"test recommendation 1\", \"test recommendation 2\"],\n"
            "    \"priority_actions\": [\"priority 1\", \"priority 2\"]\n"
            "  }\n"
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
        f"1. Identify every security vulnerability and best-practice violation.\n"
        f"2. For each issue, provide a clear 'Root Problem', 'Suggested Solution', and'Suggested Fix'.\n"
        f"3. Each 'Suggested Fix' MUST include real, actionable code examples or exact remediation steps.\n"
        f"4. Where possible, include 'source_code' with the problematic snippet and 'fixed_code' with the corrected version.\n"
        f"5. Add an 'overall_code_review' section for this file with professional commentary on strengths, risks, maintainability, test strategy, and priority actions.\n"
        f"{'6. Suggest 2-3 ways to improve this project (for learning purposes).' if 'Student' in persona else ''}\n\n"
        f"Code Content:\n"
        f"---\n"
        f"{content}\n"
        f"---\n\n"
        f"RESPOND WITH ONLY VALID JSON, NO MARKDOWN CODE BLOCKS, NO EXTRA TEXT."
    )

    try:
        ai_output = call_provider_with_json_prompt(user_prompt, system_rules, api_key, provider, current_temp)
    except Exception as e:
        logger.error(f"Unexpected error in analyze_code_logic: {e}")
        return {"status": "ERROR", "stats": {"High": 0, "Medium": 0, "Low": 0}, "findings": [{"file_name": filename, "issue_description": f"Analysis Error: {redact_sensitive_text(e)}", "suggested_fix": "Try again or contact support."}]}

    parsed = parse_ai_response(ai_output, filename)
    parsed["scanned_file_name"] = filename

    # Ensure every finding is tied to the correct file, even if the model omitted file_name.
    for finding in parsed.get("findings", []):
        if not finding.get("file_name"):
            finding["file_name"] = filename

    # Force a dedicated per-file review if the model did not return a substantive one.
    existing_review = parsed.get("overall_code_review", {})
    if not review_has_substance(existing_review):
        parsed["overall_code_review"] = generate_file_overall_review(
            filename,
            content,
            parsed.get("findings", []),
            persona,
            api_key,
            provider
        )

    return parsed

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

    # Seed every scanned file, including files with zero findings.
    for res in results_list:
        scanned_file_name = res.get("scanned_file_name")
        if scanned_file_name and scanned_file_name not in findings_by_file:
            findings_by_file[scanned_file_name] = []

    for finding in all_findings:
        filename = finding.get("file_name", "unknown")
        if filename not in findings_by_file:
            findings_by_file[filename] = []
        findings_by_file[filename].append(finding)

    # Collect professional file-level code reviews generated by the model.
    overall_reviews_by_file = {}
    for res in results_list:
        file_findings = res.get("findings", [])
        review = res.get("overall_code_review")
        filename = res.get("scanned_file_name")
        if not filename and file_findings and isinstance(file_findings, list):
            filename = file_findings[0].get("file_name")

        if not filename:
            continue

        if isinstance(review, dict):
            overall_reviews_by_file[filename] = review
        else:
            overall_reviews_by_file[filename] = build_fallback_file_review(file_findings)

    # Ensure every scanned file has a professional review section.
    for filename, findings in findings_by_file.items():
        if filename not in overall_reviews_by_file:
            overall_reviews_by_file[filename] = build_fallback_file_review(findings)
    
    result = {
        "status": final_status,
        "stats": total_stats,
        "findings": all_findings,
        "findings_by_file": findings_by_file,
        "overall_reviews_by_file": overall_reviews_by_file
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


def _build_cached_report_payload(combined: Dict[str, Any], persona: str, username: str) -> Dict[str, Any]:
    return {
        "results": {
            "status": combined["status"],
            "findings_by_file": combined["findings_by_file"],
            "overall_reviews_by_file": combined.get("overall_reviews_by_file", {}),
            "executive_summary": combined.get("executive_summary", {}),
            "security_score": combined.get("security_score", {}),
        },
        "stats": combined["stats"],
        "persona": persona,
        "username": username,
        "improvement_suggestions": combined.get("improvement_suggestions", []),
        "security_score": combined.get("security_score", {}),
        "created_at": time.time(),
    }


def _build_scan_history_entry(
    report_id: str,
    combined: Dict[str, Any],
    persona: str,
    provider: Optional[str],
    username: str,
    source: str,
) -> Dict[str, Any]:
    return {
        "scan_id": report_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "persona": persona,
        "provider": provider or "auto",
        "status": combined["status"],
        "stats": combined["stats"],
        "findings": combined["findings"],
        "findings_by_file": combined["findings_by_file"],
        "overall_reviews_by_file": combined.get("overall_reviews_by_file", {}),
        "executive_summary": combined.get("executive_summary", {}),
        "security_score": combined.get("security_score", {}),
        "username": username,
        "improvement_suggestions": combined.get("improvement_suggestions", []),
        "source": source,
    }

def process_file_content(files: List[UploadFile]) -> List[Dict]:
    raw_files: List[Dict[str, Any]] = []
    for file in files:
        if not file.filename:
            continue
        file.file.seek(0, 2)
        size = file.file.tell()
        file.file.seek(0)
        raw_files.append({
            "name": file.filename,
            "size": size,
            "content_bytes": file.file.read(),
        })
    return process_raw_file_payloads(raw_files)


def process_raw_file_payloads(raw_files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    files_to_scan: List[Dict[str, str]] = []
    total_size = 0

    for file in raw_files:
        filename = str(file.get("name", ""))
        if not filename:
            continue

        if len(files_to_scan) >= MAX_FILES_PER_SCAN:
            logger.warning(f"Scan limit reached: maximum {MAX_FILES_PER_SCAN} files allowed.")
            break

        size = int(file.get("size", 0))
        if size > MAX_FILE_SIZE:
            logger.warning(f"File {filename} too large: {size} bytes. Skipping.")
            continue

        total_size += size
        if total_size > MAX_TOTAL_SCAN_SIZE:
            logger.warning("Total scan size limit reached. Skipping remaining files.")
            break

        content_bytes = file.get("content_bytes", b"")
        if not isinstance(content_bytes, (bytes, bytearray)):
            continue

        if filename.lower().endswith(".zip"):
            try:
                files_to_scan.extend(_extract_supported_files_from_zip_bytes(filename, content_bytes))
            except Exception as e:
                logger.error(f"ZIP parsing error for {filename}: {e}")
        else:
            if not is_supported_source_file(filename):
                continue
            files_to_scan.append({
                "name": filename,
                "content": bytes(content_bytes).decode("utf-8", errors="ignore"),
            })

    return files_to_scan


def fetch_github_repo_files(github_url: str) -> Dict[str, Any]:
    # Advanced URL parsing: support owner/repo and owner/repo/tree/branch forms.
    clean_url = github_url.split('?')[0].rstrip('/')
    url_parts = clean_url.split('/')

    try:
        github_index = next(i for i, part in enumerate(url_parts) if "github.com" in part)
        owner = url_parts[github_index + 1]
        repo = url_parts[github_index + 2]
        if repo.endswith(".git"):
            repo = repo[:-4]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
            raise HTTPException(status_code=400, detail="Invalid GitHub repository identifier")

        target_branch = None
        if len(url_parts) > github_index + 4 and url_parts[github_index + 3] == "tree":
            target_branch = url_parts[github_index + 4]
            logger.info(f"Target branch from URL: {target_branch}")
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL. Use format: https://github.com/owner/repo or https://github.com/owner/repo/tree/branch")

    zip_response = None
    tried_branches: List[str] = []
    branches_to_try: List[str] = []

    if target_branch:
        branches_to_try.append(target_branch)
    else:
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

    for branch_name in ["main", "master"]:
        if branch_name not in branches_to_try:
            branches_to_try.append(branch_name)

    logger.info(f"Attempting to download from [{owner}/{repo}] branches: {branches_to_try}")
    for branch in branches_to_try:
        try:
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{requests.utils.quote(branch, safe='')}.zip"
            tried_branches.append(branch)
            resp = requests.get(zip_url, timeout=30, allow_redirects=True, headers={"User-Agent": "CodeGuard-AI/1.0"})
            if resp.status_code == 200:
                logger.info(f"Found valid branch: {branch}")
                zip_response = resp
                break
            if resp.status_code == 404:
                continue
            logger.warning(f"Unexpected status {resp.status_code} for branch {branch}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for branch {branch}: {e}")

    if zip_response is None or zip_response.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Could not download repository '{owner}/{repo}'. Tried branches: {', '.join(tried_branches)}. Ensure it is public and valid.",
        )

    files_to_scan = _extract_supported_files_from_zip_bytes(f"{owner}/{repo}.zip", zip_response.content)
    if not files_to_scan:
        raise HTTPException(status_code=400, detail="No valid source files found in repo.")

    return {
        "owner": owner,
        "repo": repo,
        "files_to_scan": files_to_scan,
    }


def run_hybrid_analysis_for_files(
    files_to_scan: List[Dict[str, str]],
    effective_key: str,
    persona: str,
    provider: Optional[str],
) -> List[Dict[str, Any]]:
    individual_results: List[Dict[str, Any]] = []
    for scanned_file in files_to_scan:
        filename = scanned_file["name"]
        content = scanned_file["content"]
        llm_result = analyze_code_logic(filename, content, effective_key, persona, provider)
        sast_findings = run_lightweight_sast(filename, content)
        merged = merge_hybrid_findings(llm_result, sast_findings, filename)
        individual_results.append(merged)
    return individual_results


async def run_hybrid_analysis_for_files_async(
    scan_id: str,
    files_to_scan: List[Dict[str, str]],
    effective_key: str,
    persona: str,
    provider: Optional[str],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    total_files = max(1, len(files_to_scan))
    for index, scanned_file in enumerate(files_to_scan, start=1):
        filename = scanned_file["name"]
        _set_scan_task(
            scan_id,
            status="running",
            phase="analyzing_file",
            current_file=filename,
            progress_percent=int(((index - 1) / total_files) * 100),
            message=f"Analyzing {filename} ({index}/{total_files})",
        )
        await notify_scan_subscribers(scan_id)

        llm_result = await asyncio.to_thread(analyze_code_logic, filename, scanned_file["content"], effective_key, persona, provider)
        sast_findings = run_lightweight_sast(filename, scanned_file["content"])
        merged = merge_hybrid_findings(llm_result, sast_findings, filename)
        results.append(merged)

        _set_scan_task(
            scan_id,
            progress_percent=int((index / total_files) * 100),
            message=f"Completed {filename}",
        )
        await notify_scan_subscribers(scan_id)

    return results


async def run_async_scan_job(
    scan_id: str,
    files_to_scan: List[Dict[str, str]],
    persona: str,
    effective_key: str,
    provider: Optional[str],
    username: str,
    source: str,
) -> None:
    try:
        _set_scan_task(
            scan_id,
            status="running",
            phase="queued",
            progress_percent=0,
            message="Scan queued",
            report_id=None,
            result=None,
            error=None,
        )
        await notify_scan_subscribers(scan_id)

        individual_results = await run_hybrid_analysis_for_files_async(scan_id, files_to_scan, effective_key, persona, provider)
        combined = combine_results(individual_results)

        _set_scan_task(scan_id, phase="generating_summary", message="Generating executive summary")
        await notify_scan_subscribers(scan_id)
        combined["executive_summary"] = await asyncio.to_thread(
            generate_executive_vulnerability_summary,
            combined.get("findings", []),
            persona,
            effective_key,
            provider,
        )
        combined["security_score"] = compute_security_score(
            combined.get("stats", {}),
            len(combined.get("findings_by_file", {})),
            combined.get("status", "SAFE"),
        )

        REPORT_CACHE[scan_id] = _build_cached_report_payload(combined, persona, username)
        append_scan_history(_build_scan_history_entry(scan_id, combined, persona, provider, username, source))

        final_payload = {
            "report_id": scan_id,
            "scan_id": scan_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "security_score": combined.get("security_score", {}),
            "findings": combined["findings"],
            "overall_reviews_by_file": combined.get("overall_reviews_by_file", {}),
            "executive_summary": combined.get("executive_summary", {}),
            "improvement_suggestions": combined.get("improvement_suggestions", []),
        }

        _set_scan_task(
            scan_id,
            status="completed",
            phase="done",
            progress_percent=100,
            message="Scan completed",
            report_id=scan_id,
            result=final_payload,
        )
        await notify_scan_subscribers(scan_id)
    except Exception as e:
        safe_error = redact_sensitive_text(e)
        logger.error(f"Async scan task failed for {scan_id}: {safe_error}")
        _set_scan_task(
            scan_id,
            status="failed",
            phase="failed",
            progress_percent=100,
            message="Scan failed",
            error=safe_error,
            result={
                "report_id": scan_id,
                "status": "ERROR",
                "stats": {"High": 0, "Medium": 0, "Low": 0},
                "security_score": compute_security_score({"High": 0, "Medium": 0, "Low": 0}, 0, "ERROR"),
                "findings": [{
                    "file_name": "unknown",
                    "issue_description": f"Analysis Error: {safe_error}",
                    "suggested_fix": "Retry analysis and verify provider credentials and connectivity.",
                }],
                "improvement_suggestions": [],
            },
        )
        await notify_scan_subscribers(scan_id)

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
    effective_key = ""
    api_key = None
    try:
        authenticated_user = get_optional_authenticated_user(request)
        logger.info(f"=== ANALYZE REQUEST START ===")
        persona = _validate_persona(persona)
        provider = _validate_provider(provider)
        api_key = _validate_api_key(api_key)
        username = _validate_optional_username(username)

        if api_key and not ALLOW_CLIENT_API_KEYS:
            raise HTTPException(
                status_code=400,
                detail="Direct API key submission is disabled. Configure DEFAULT_GROQ_API_KEY on the server.",
            )

        if len(files) > MAX_FILES_PER_SCAN:
            raise HTTPException(status_code=400, detail=f"Too many files submitted. Max allowed: {MAX_FILES_PER_SCAN}")

        # Resolve effective API key: user-supplied > server default
        effective_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""
        using_server_key = bool(not (api_key or "").strip() and DEFAULT_GROQ_API_KEY)
        logger.info(f"API Key source: {'user-supplied' if not using_server_key else 'server-default-groq'}")
        logger.info(f"Persona: {persona}")
        logger.info(f"Provider: {provider}")
        
        # Generate unique report ID
        report_id = str(uuid.uuid4())
        logger.info(f"Generated Report ID: {report_id}")
        
        files_to_scan = process_file_content(files)
        logger.info(f"Files to scan: {len(files_to_scan)}")
        
        if not files_to_scan:
            return JSONResponse(status_code=400, content={"message": "No valid source files found or invalid format."})
             
        individual_results = run_hybrid_analysis_for_files(files_to_scan, effective_key, persona, provider)
        
        # Combine all individual results into a single report
        combined = combine_results(individual_results)
        combined["executive_summary"] = generate_executive_vulnerability_summary(
            combined.get("findings", []),
            persona,
            effective_key,
            provider
        )
        combined["security_score"] = compute_security_score(
            combined.get("stats", {}),
            len(combined.get("findings_by_file", {})),
            combined.get("status", "SAFE"),
        )
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
        
        REPORT_CACHE[report_id] = _build_cached_report_payload(
            combined,
            persona,
            username or "anonymous",
        )

        effective_username = authenticated_user or username or "anonymous"
        scan_history_entry = _build_scan_history_entry(
            report_id,
            combined,
            persona,
            provider,
            effective_username,
            "local_upload",
        )
        append_scan_history(scan_history_entry)
        
        return JSONResponse(content={
            "report_id": report_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "security_score": combined.get("security_score", {}),
            "findings": combined["findings"],
            "overall_reviews_by_file": combined.get("overall_reviews_by_file", {}),
            "executive_summary": combined.get("executive_summary", {}),
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        })
        
    except Exception as e:
        logger.error(f"Error processing analysis: {redact_sensitive_text(e)}")
        return build_error_scan_response(
            "An unexpected error occurred while processing the analysis request.",
            report_id=locals().get("report_id"),
        )
    finally:
        # Reduce secret lifetime in request-local variables.
        effective_key = ""
        api_key = None

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
    api_key = None
    try:
        authenticated_user = get_optional_authenticated_user(request)
        github_url = _validate_github_url(github_url)
        persona = _validate_persona(persona)
        provider = _validate_provider(provider)
        api_key = _validate_api_key(api_key)
        username = _validate_optional_username(username)

        if api_key and not ALLOW_CLIENT_API_KEYS:
            raise HTTPException(
                status_code=400,
                detail="Direct API key submission is disabled. Configure DEFAULT_GROQ_API_KEY on the server.",
            )

        # Resolve effective API key: user-supplied > server default
        api_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""

        github_data = fetch_github_repo_files(github_url)
        owner = github_data["owner"]
        repo = github_data["repo"]
        files_to_scan = github_data["files_to_scan"]
        report_id = str(uuid.uuid4())
             
        individual_results = run_hybrid_analysis_for_files(files_to_scan, api_key, persona, provider)
        
        combined = combine_results(individual_results)
        combined["executive_summary"] = generate_executive_vulnerability_summary(
            combined.get("findings", []),
            persona,
            api_key,
            provider
        )
        combined["security_score"] = compute_security_score(
            combined.get("stats", {}),
            len(combined.get("findings_by_file", {})),
            combined.get("status", "SAFE"),
        )
        
        REPORT_CACHE[report_id] = _build_cached_report_payload(
            combined,
            persona,
            username or "anonymous",
        )

        effective_username = authenticated_user or username or "anonymous"
        scan_history_entry = _build_scan_history_entry(
            report_id,
            combined,
            persona,
            provider,
            effective_username,
            f"github:{owner}/{repo}",
        )
        append_scan_history(scan_history_entry)
        
        return JSONResponse(content={
            "report_id": report_id,
            "status": combined["status"],
            "stats": combined["stats"],
            "security_score": combined.get("security_score", {}),
            "findings": combined["findings"],
            "overall_reviews_by_file": combined.get("overall_reviews_by_file", {}),
            "executive_summary": combined.get("executive_summary", {}),
            "improvement_suggestions": combined.get("improvement_suggestions", [])
        })
        
    except Exception as e:
        logger.error(f"Error processing github analysis: {redact_sensitive_text(e)}")
        return build_error_scan_response(
            "An unexpected error occurred while processing the GitHub analysis request.",
            report_id=locals().get("report_id"),
        )
    finally:
        # Reduce secret lifetime in request-local variables.
        api_key = None


@app.get("/explore-engine")
@limiter.limit("60/minute")
async def explore_engine_endpoint(request: Request):
    get_optional_authenticated_user(request)

    has_server_groq_key = bool((DEFAULT_GROQ_API_KEY or "").strip())
    client_keys_enabled = ALLOW_CLIENT_API_KEYS

    engines = [
        {
            "id": "groq",
            "name": "Groq Engine",
            "available": bool(has_server_groq_key or client_keys_enabled),
            "requires_client_api_key": bool(not has_server_groq_key),
        },
        {
            "id": "openai",
            "name": "OpenAI Matrix",
            "available": bool(client_keys_enabled),
            "requires_client_api_key": True,
        },
        {
            "id": "gemini",
            "name": "Gemini Core",
            "available": bool(client_keys_enabled),
            "requires_client_api_key": True,
        },
    ]

    default_engine = "groq" if engines[0]["available"] else "auto"
    if default_engine == "auto":
        for engine in engines:
            if engine["available"]:
                default_engine = engine["id"]
                break

    return {
        "engines": engines,
        "default_engine": default_engine,
        "client_api_keys_enabled": client_keys_enabled,
    }


@app.post("/initialize-scan", response_model=AsyncScanResponse)
@limiter.limit("10/hour")
async def initialize_scan_endpoint(request: Request, payload: InitializeScanRequest):
    authenticated_user = get_optional_authenticated_user(request)

    github_url = _validate_github_url(payload.github_url)
    persona = _validate_persona(payload.persona)
    provider = _validate_provider(payload.provider)
    api_key = _validate_api_key(payload.api_key)
    username = _validate_optional_username(payload.username)

    if api_key and not ALLOW_CLIENT_API_KEYS:
        raise HTTPException(
            status_code=400,
            detail="Direct API key submission is disabled. Configure DEFAULT_GROQ_API_KEY on the server.",
        )

    effective_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""
    github_data = fetch_github_repo_files(github_url)
    owner = github_data["owner"]
    repo = github_data["repo"]
    files_to_scan = github_data["files_to_scan"]

    scan_id = str(uuid.uuid4())
    effective_username = authenticated_user or username or "anonymous"
    source = f"github:{owner}/{repo}"

    _set_scan_task(
        scan_id,
        scan_id=scan_id,
        report_id=None,
        status="queued",
        phase="queued",
        progress_percent=0,
        message="Scan accepted",
        source=source,
        user=effective_username,
        created_at=_utc_timestamp(),
        current_file=None,
        result=None,
        error=None,
        provider=provider or "auto",
        persona=persona,
        total_files=len(files_to_scan),
    )
    await notify_scan_subscribers(scan_id)

    asyncio.create_task(
        run_async_scan_job(
            scan_id=scan_id,
            files_to_scan=files_to_scan,
            persona=persona,
            effective_key=effective_key,
            provider=provider,
            username=effective_username,
            source=source,
        )
    )

    return AsyncScanResponse(scan_id=scan_id, status="queued", ws_path=f"/ws/scans/{scan_id}")

@app.get("/history")
@limiter.limit("60/minute")
async def get_scan_history(request: Request, username: Optional[str] = None):
    auth_user = get_authenticated_user(request)
    target_user = auth_user
    history = load_scan_history()
    if target_user:
        history = [entry for entry in history if entry.get("username", "anonymous") == target_user]
    return {"history": history[::-1]}  # Return reversed (latest first)

@app.get("/compare")
@limiter.limit("40/minute")
async def compare_scans(request: Request, scan_a: str, scan_b: str):
    auth_user = get_authenticated_user(request)
    scan_a = _validate_uuid_field(scan_a, "scan_a", MAX_SCAN_ID_LEN)
    scan_b = _validate_uuid_field(scan_b, "scan_b", MAX_SCAN_ID_LEN)

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
    auth_user = get_authenticated_user(request)
    report_id = _validate_uuid_field(report_id, "report_id", MAX_REPORT_ID_LEN)

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
                    "overall_reviews_by_file": match.get("overall_reviews_by_file", {}),
                    "executive_summary": match.get("executive_summary", {}),
                    "security_score": match.get("security_score", {}),
                },
                "stats": match.get("stats"),
                "persona": match.get("persona"),
                "username": match.get("username", "anonymous"),
                "improvement_suggestions": match.get("improvement_suggestions", []),
                "security_score": match.get("security_score", {}),
            }
        else:
            logger.error(f"Report ID {report_id} not found in cache or history")
            raise HTTPException(status_code=404, detail="Report ID not found or expired")

    report_owner = cached.get("username", "anonymous")
    if report_owner != auth_user:
        raise HTTPException(status_code=403, detail="You are not allowed to export this report")
    
    logger.info(f"Data available for PDF: Persona={cached.get('persona')}, Results={len(cached.get('results', {}).get('findings_by_file', {}))} files")
    
    try:
        report_username = cached.get("username", "anonymous")
        pdf_bytes = generate_pdf_report(
            cached["results"],
            cached["stats"],
            cached["persona"],
            cached.get("improvement_suggestions", []),
            report_username,
            cached.get("results", {}).get("overall_reviews_by_file", {}),
            cached.get("results", {}).get("executive_summary", {})
        )
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
        logger.error(f"PDF generation error: {redact_sensitive_text(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="PDF generation failed")


@app.get("/export-patch")
@limiter.limit("10/minute")
async def export_patch_endpoint(request: Request, report_id: str, username: Optional[str] = None):
    auth_user = get_authenticated_user(request)
    report_id = _validate_uuid_field(report_id, "report_id", MAX_REPORT_ID_LEN)

    cached = REPORT_CACHE.get(report_id)
    if not cached:
        history = load_scan_history()
        match = next((h for h in history if h.get("scan_id") == report_id), None)
        if match:
            cached = {
                "results": {
                    "findings_by_file": match.get("findings_by_file", {}),
                },
                "username": match.get("username", "anonymous"),
            }
        else:
            raise HTTPException(status_code=404, detail="Report ID not found or expired")

    report_owner = cached.get("username", "anonymous")
    if report_owner != auth_user:
        raise HTTPException(status_code=403, detail="You are not allowed to export this report")
    
    findings_by_file = cached.get("results", {}).get("findings_by_file", {})
    patch_lines = []
    
    for file_name, findings in findings_by_file.items():
        for i, finding in enumerate(findings):
            source_c = str(finding.get("source_code") or "").strip()
            fixed_c = str(finding.get("fixed_code") or "").strip()
            if source_c and fixed_c and source_c != fixed_c:
                diff_str = build_fix_preview_diff(file_name, source_c, fixed_c)
                if diff_str:
                    patch_lines.append(f"--- Fix {i} for {file_name} ---\n{diff_str}\n")
    
    patch_content = "\n".join(patch_lines)
    if not patch_content:
        raise HTTPException(status_code=404, detail="No code fixes found for this report. The AI may not have provided exact source code diffs.")
    
    return StreamingResponse(
        io.BytesIO(patch_content.encode("utf-8")),
        media_type="text/x-patch",
        headers={
            "Content-Disposition": f"attachment; filename=\"remediations_{report_id}.patch\""
        }
    )


@app.post("/analyze-async", response_model=AsyncScanResponse)
@limiter.limit("10/hour")
async def analyze_async_endpoint(
    request: Request,
    files: List[UploadFile] = File(...),
    persona: str = Form("Student"),
    api_key: Optional[str] = Form(None),
    provider: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
):
    authenticated_user = get_optional_authenticated_user(request)
    persona = _validate_persona(persona)
    provider = _validate_provider(provider)
    api_key = _validate_api_key(api_key)
    username = _validate_optional_username(username)

    if api_key and not ALLOW_CLIENT_API_KEYS:
        raise HTTPException(
            status_code=400,
            detail="Direct API key submission is disabled. Configure DEFAULT_GROQ_API_KEY on the server.",
        )

    if len(files) > MAX_FILES_PER_SCAN:
        raise HTTPException(status_code=400, detail=f"Too many files submitted. Max allowed: {MAX_FILES_PER_SCAN}")

    effective_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""

    raw_files: List[Dict[str, Any]] = []
    for uploaded in files:
        if not uploaded.filename:
            continue
        uploaded.file.seek(0, 2)
        size = uploaded.file.tell()
        uploaded.file.seek(0)
        raw_files.append({
            "name": uploaded.filename,
            "size": size,
            "content_bytes": uploaded.file.read(),
        })

    files_to_scan = process_raw_file_payloads(raw_files)
    if not files_to_scan:
        raise HTTPException(status_code=400, detail="No valid source files found or invalid format.")

    scan_id = str(uuid.uuid4())
    effective_username = authenticated_user or username or "anonymous"

    _set_scan_task(
        scan_id,
        scan_id=scan_id,
        report_id=None,
        status="queued",
        phase="queued",
        progress_percent=0,
        message="Scan accepted",
        source="local_upload",
        user=effective_username,
        created_at=_utc_timestamp(),
        current_file=None,
        result=None,
        error=None,
        provider=provider or "auto",
        persona=persona,
        total_files=len(files_to_scan),
    )
    await notify_scan_subscribers(scan_id)

    asyncio.create_task(
        run_async_scan_job(
            scan_id=scan_id,
            files_to_scan=files_to_scan,
            persona=persona,
            effective_key=effective_key,
            provider=provider,
            username=effective_username,
            source="local_upload",
        )
    )

    return AsyncScanResponse(scan_id=scan_id, status="queued", ws_path=f"/ws/scans/{scan_id}")


@app.get("/scan-status/{scan_id}")
@limiter.limit("120/minute")
async def get_scan_status(request: Request, scan_id: str):
    auth_user = get_authenticated_user(request)
    scan_id = _validate_uuid_field(scan_id, "scan_id", MAX_SCAN_ID_LEN)
    task = get_scan_task(scan_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    if task.get("user") != auth_user:
        raise HTTPException(status_code=403, detail="You are not allowed to access this scan")
    return task


@app.websocket("/ws/scans/{scan_id}")
async def scan_updates_websocket(websocket: WebSocket, scan_id: str):
    try:
        parsed_scan_id = str(uuid.UUID(scan_id))
    except Exception:
        await websocket.accept()
        await websocket.send_json({"status": "failed", "error": "Invalid scan_id format"})
        await websocket.close()
        return

    token = websocket.query_params.get("token", "").strip()
    username = verify_auth_token(token) if token else None
    task = get_scan_task(parsed_scan_id)
    if not username or not task or task.get("user") != username:
        await websocket.accept()
        await websocket.send_json({"status": "failed", "error": "Unauthorized websocket subscription"})
        await websocket.close()
        return

    await register_scan_socket(parsed_scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        unregister_scan_socket(parsed_scan_id, websocket)
    except Exception:
        unregister_scan_socket(parsed_scan_id, websocket)


@app.post("/apply-fix-preview")
@limiter.limit("30/minute")
async def apply_fix_preview_endpoint(request: Request, payload: ApplyFixRequest):
    get_authenticated_user(request)
    file_name = _validate_text_field(payload.file_name, "file_name", 512, required=True)
    source_code = payload.source_code or ""
    fixed_code = payload.fixed_code or ""
    file_name = _safe_diff_filename(file_name)

    if len(source_code) > 1_000_000 or len(fixed_code) > 1_000_000:
        raise HTTPException(status_code=400, detail="Source or fixed code exceeds size limits")

    if source_code == fixed_code:
        return {
            "file_name": file_name,
            "changed": False,
            "diff": "",
            "message": "No changes detected between source and fixed code.",
        }

    diff = build_fix_preview_diff(file_name, source_code, fixed_code)
    if not diff:
        diff = "(No textual diff generated; verify newline normalization or binary content.)"

    return {
        "file_name": file_name,
        "changed": True,
        "diff": diff,
        "message": "Preview generated. Validate side effects with tests before applying fixes.",
    }


@app.post("/api/logout")
async def logout(response: Response):
    _clear_auth_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return {"message": "Logged out"}

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
        if len(files) > MAX_FILES_PER_SCAN:
            raise HTTPException(status_code=400, detail=f"Too many files submitted. Max allowed: {MAX_FILES_PER_SCAN}")
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
        logger.error(f"Dependency scan error: {redact_sensitive_text(e)}")
        raise HTTPException(status_code=500, detail="Dependency scan failed")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("UVICORN_HOST", "127.0.0.1")
    uvicorn.run("app:app", host=host, port=port, reload=(ENV_MODE == "development"))

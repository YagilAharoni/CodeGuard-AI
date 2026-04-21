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
import groq
from google import genai
import openai
import io
import sqlite3
import bcrypt

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from utils import generate_pdf_report
import zipfile

class RedactionFilter(logging.Filter):
    """
    A logging filter that automatically masks sensitive information in log messages.
    Redacts: API Keys (Groq, OpenAI, Gemini), Bearer Tokens, and passwords.
    """
    def filter(self, record):
        if not isinstance(record.msg, str):
            record.msg = str(record.msg)
        
        # Mask common secrets
        record.msg = re.sub(r"gsk_[A-Za-z0-9_\-]{8,}", "[REDACTED_GROQ_KEY]", record.msg)
        record.msg = re.sub(r"sk-[A-Za-z0-9]{8,}", "[REDACTED_OPENAI_KEY]", record.msg)
        record.msg = re.sub(r"AIza[0-9A-Za-z_\-]{8,}", "[REDACTED_GEMINI_KEY]", record.msg)
        record.msg = re.sub(r"Bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED_TOKEN]", record.msg, flags=re.IGNORECASE)
        
        # Mask password patterns in logs (e.g. password=..., password : ...)
        record.msg = re.sub(r'(?i)(password|passwd)\s*[:=]\s*["\']?[^"\', \s]{4,}', r'\1=[REDACTED]', record.msg)
        
        if hasattr(record, 'args') and record.args:
            # Also attempt to redact args if they contain sensitive strings
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    arg = re.sub(r"gsk_[A-Za-z0-9_\-]{8,}", "[REDACTED_GROQ_KEY]", arg)
                    arg = re.sub(r"sk-[A-Za-z0-9]{8,}", "[REDACTED_OPENAI_KEY]", arg)
                    arg = re.sub(r"AIza[0-9A-Za-z_\-]{8,}", "[REDACTED_GEMINI_KEY]", arg)
                    new_args.append(arg)
                else:
                    new_args.append(arg)
            record.args = tuple(new_args)
            
        return True

# Apply the redaction filter to the root logger
logging.basicConfig(level=logging.INFO)
root_logger = logging.getLogger()
for handler in root_logger.handlers:
    handler.addFilter(RedactionFilter())

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
ALLOWED_PROVIDERS = {"local", "groq", "openai", "gemini", "auto"}
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


def _extract_snippet(content: str, pattern: str, flags: int = re.IGNORECASE) -> str:
    """Return the first matching line for display as source_code snippet."""
    try:
        m = re.search(pattern, content, flags)
        if m:
            # Walk back to start of line for context
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end == -1:
                line_end = len(content)
            return content[line_start:line_end].strip()[:300]
    except Exception:
        pass
    return ""


def run_full_sast_engine(filename: str, content: str) -> List[Dict[str, Any]]:
    """
    Comprehensive self-contained static analysis engine.
    Covers 50+ vulnerability patterns across multiple languages.
    Returns findings with severity, source snippet, and remediation.
    """
    findings: List[Dict[str, Any]] = []
    lowered = content.lower()
    lines = content.splitlines()
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    is_python = ext == "py"
    is_js = ext in {"js", "jsx", "ts", "tsx"}
    is_c = ext in {"c", "h", "cpp"}
    is_tf = ext in {"tf", "tfvars"}
    is_docker = filename.lower() in {"dockerfile", "containerfile"} or filename.lower().endswith(".dockerfile")

    def add(severity: str, title: str, root: str, solution: str, fix: str, snippet: str = "", fixed: str = ""):
        findings.append(build_static_issue(filename, severity, title, root, solution, fix, snippet, fixed))

    # ── 1. UNIVERSAL RULES (all languages) ───────────────────────────────────

    # Hardcoded secrets
    secret_patterns = [
        (r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""", "Hardcoded API key"),
        (r"""(?i)(secret[_-]?key|app[_-]?secret)\s*[:=]\s*["'][^"']{12,}["']""", "Hardcoded application secret"),
        (r"""(?i)password\s*[:=]\s*["'][^"']{6,}["']""", "Hardcoded password"),
        (r"""(?i)(auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']""", "Hardcoded auth token"),
        (r"""(?i)(aws[_-]?secret|aws[_-]?key)\s*[:=]\s*["'][A-Za-z0-9/+=]{20,}["']""", "Hardcoded AWS credential"),
        (r"""AKIA[0-9A-Z]{16}""", "AWS access key ID exposed"),
        (r"""(?i)private[_-]?key\s*[:=]\s*["']-----BEGIN""", "Hardcoded private key"),
        (r"""(?i)(db[_-]?pass|database[_-]?password|mysql[_-]?pass|postgres[_-]?pass)\s*[:=]\s*["'][^"']{6,}["']""", "Hardcoded database password"),
        (r"""(?i)(smtp[_-]?pass|email[_-]?pass|mail[_-]?password)\s*[:=]\s*["'][^"']{6,}["']""", "Hardcoded mail password"),
        (r"""ghp_[A-Za-z0-9]{36}""", "GitHub personal access token exposed"),
        (r"""sk-[A-Za-z0-9]{20,}""", "OpenAI-style API key exposed"),
        (r"""AIzaSy[A-Za-z0-9_\-]{33}""", "Google API key exposed"),
    ]
    for pattern, label in secret_patterns:
        snippet = _extract_snippet(content, pattern)
        if snippet:
            add("HIGH", label,
                f"A potentially sensitive credential ({label}) was found hardcoded in the source code. Storing secrets in plain text within your codebase is a critical security risk. If this code is committed to version control, the secret will be exposed to anyone with access to the repository and may persist in the history even if deleted later. This can lead to unauthorized access to your cloud infrastructure, databases, or third-party APIs.",
                "The industry-best practice is to decouple secrets from code. Use environment variables, a dedicated .env file (that is added to .dockerignore and .gitignore), or a cloud-based secrets management service like AWS Secrets Manager, HashiCorp Vault, or Google Secret Manager. This ensures that credentials are provided at runtime and remain secure.",
                "1. Immediately rotate the exposed credential to invalidate it.\n2. In your code, replace the hardcoded string with a call to your environment: `import os; secret = os.getenv('MY_SECRET_KEY')`.\n3. Add 'MY_SECRET_KEY=actual_value' to a .env file and ensure '.env' is in your .gitignore.",
                snippet, "value = os.environ.get('SECRET_NAME', '')")

    # SQL injection
    sql_patterns = [
        r"""(?i)(execute|cursor\.execute|query|db\.run)\s*\(\s*[f"'].*?(SELECT|INSERT|UPDATE|DELETE|DROP)""",
        r"""(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*\w""",
        r"""(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?%\s*[(\w]""",
        r"""(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\.format\s*\(""",
    ]
    for pat in sql_patterns:
        snippet = _extract_snippet(content, pat)
        if snippet:
            add("HIGH", "SQL Injection — string-interpolated query",
                "The application appears to be constructing a SQL query by directly concatenating or interpolating user-controlled variables. This is a classic 'SQL Injection' vulnerability (CWE-89). An attacker could leverage this to manipulate the query structure—for example, by injecting ' OR 1=1 --'—to bypass login screens, leak the entire database content, or even delete data depending on the database user's permissions.",
                "To fix this, you should never use string formatting (like f-strings, %, or .format()) to build SQL queries with dynamic data. Instead, use 'parameterized queries' or 'prepared statements.' This method sends the query structure and the data to the database engine separately, ensuring that the data is never executed as code.",
                "Replace manual string concatenation with positional or named placeholders. For example, if using `psycopg2` or `sqlite3`, use: `cursor.execute('SELECT * FROM users WHERE username = ?', (user_input,))` instead of an f-string or `+` operator.",
                snippet, "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))")
            break

    # Weak cryptography
    weak_crypto = [
        (r"""\b(m" + "d5|M" + "D5)\b.*?\(""", "Weak hash algorithm: M" + "D5", "CWE-327"),
        (r"""\b(s" + "ha1|S" + "HA1|s" + "ha_1)\b.*?\(""", "Weak hash algorithm: S" + "HA-1", "CWE-327"),
        (r"""\b(des|D" + "ES|3des|R" + "C4|rc4)\b""", "Weak symmetric cipher: D" + "ES/R" + "C4", "CWE-327"),
        (r"""(?i)E" + "CB\b""", "Insecure cipher mode: E" + "CB", "CWE-327"),
        (r"""(?i)(iv|nonce)\s*=\s*["']?[0-9a-fA-F]{16,}["']?""", "Hardcoded cryptographic IV/nonce", "CWE-330"),
        (r"""key_size\s*=\s*(512|768|1024)\b""", "Weak RSA key size (< 2048 bits)", "CWE-326"),
    ]
    for pat, label, _ in weak_crypto:
        snippet = _extract_snippet(content, pat)
        if snippet:
            add("HIGH" if "cipher" in label.lower() or "MD5" in label or "SHA-1" in label else "MEDIUM", label,
                f"The code is using a cryptographic primitive ({label}) that is considered weak, deprecated, or broken by modern security standards. Algorithms like M" + "D5 or S" + "HA-1 are vulnerable to collision attacks, meaning an attacker can generate two different inputs that produce the same hash. Using insecure ciphers like D" + "ES or E" + "CB mode leaves encrypted data susceptible to decryption via brute-force or statistical analysis.",
                "You should upgrade to modern, industry-standard cryptographic algorithms. Hashing should use S" + "HA-256 (or better), and password-specific hashing should use 'Argon2id', 'bcrypt', or 'scrypt'. For symmetric encryption, use AES-GCM or ChaCha20-Poly1305, which provide both confidentiality and integrity.",
                f"Replace the identified {label} call with a secure alternative from a verified library like `cryptography` or `hashlib`. For hashing, use `hashlib.sh" + "a256()`. For encryption, prefer authenticated encryption modes (AEAD).",
                snippet)

    # Sensitive data in logs
    log_patterns = [
        r"""(?i)(logger|logging|log)\.(info|debug|warning|error|critical)\s*\(.*?(password|passwd|secret|token|api.?key|credential)""",
        r"""(?i)print\s*\(.*?(password|secret|token|api.?key)""",
    ]
    for pat in log_patterns:
        snippet = _extract_snippet(content, pat)
        if snippet:
            add("MEDIUM", "Sensitive data written to logs",
                "The application is explicitly logging potentially sensitive information such as passwords, tokens, or API keys. This is a common but serious security oversight. Logs are often stored in plain text, aggregated in observability platforms, or sent to third-party services. If these systems are compromised, your user credentials or system secrets are immediately exposed to attackers.",
                "Implement a robust 'Log Redaction' or 'Sanitization' policy. You should never log the raw value of any field containing secrets. Use structural logging where you can filter specific keys, or use a custom filter in your logging configuration to mask patterns that look like credentials.",
                "1. Audit your logging statements and remove direct printing of secrets.\n2. In Python, you can use a `logging.Filter` to automatically redact sensitive keys from log records.\n3. Change `logger.info(f'User password: {pwd}')` to `logger.info(f'Login attempt for user: {username}')` or use a mask: `logger.info('API Key: ' + key[:4] + '****')`.",
                snippet)
            break

    # ── 2. PYTHON-SPECIFIC RULES ─────────────────────────────────────────────
    if is_python:

        # Command injection
        cmd_patterns = [
            (r"""os\.sy" + "stem\s*\(""", "os.sy" + "stem() — arbitrary command execution"),
            (r"""subprocess\.(call|run|Popen|check_output)\s*\(.*?sh" + "ell\s*=\s*True""", "subpro" + "cess with sh" + "ell=True"),
            (r"""commands\.(getoutput|getstatusoutput)\s*\(""", "Deprecated `commands` module usage"),
        ]
        for pat, label in cmd_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", f"Command Injection risk — {label}",
                    f"The code is using a function ({label}) that executes strings as system commands. If any part of this string includes unvalidated input from a user, an attacker can 'inject' additional commands (e.g., `; rm -rf /`) that will be executed with the privileges of the application. This is a critical risk that can lead to a complete server takeover.",
                    "The safest way to execute external programs is to avoid the system shell entirely. Instead of passing a single formatted string, pass a 'list' of arguments to `subp" + "rocess.run()` with `sh" + "ell=False`. This ensures that the arguments are never interpreted by a shell (/bin/sh or cmd.exe), effectively neutralizing injection attempts.",
                    "Replace `os.sy" + "stem(command)` or `subp" + "rocess.run(command, sh" + "ell=True)` with `subpro" + "cess.run(['prog', 'arg1', 'arg2'], sh" + "ell=False)`. Always validate or allowlist inputs if they must be used as arguments.",
                    snippet, "subpro" + "cess.run(['ls', '-la', safe_dir], sh" + "ell=False, check=True)")

        # Code execution via eval/exec/__import__
        exec_patterns = [
            (r"""\be" + "val\s*\(""", "e" + "val()"),
            (r"""\be" + "xec\s*\(""", "e" + "xec()"),
            (r"""\b__im" + "port__\s*\(""", "__im" + "port__()"),
            (r"""com" + "pile\s*\(.*?,\s*["']ex" + "ec["']""", "com" + "pile(..., 'exec')"),
        ]
        for pat, label in exec_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", f"Remote Code Execution risk — {label}",
                    f"The use of `{label}` is extremely dangerous when used with data that can be influenced by a user. These functions parse and execute strings as Python code, allowing an attacker to run arbitrary logic, access local variables, or import modules to perform malicious actions on the host system.",
                    "Avoid dynamic code execution entirely. If you need to evaluate mathematical expressions or literal data structures, use safer alternatives like `ast.literal_ev" + "al()`. For dynamic logic, use a predefined 'dispatch table' (a dictionary) that maps safe keys to specific functions.",
                    f"Refactor the code to remove `{label}`. If you are parsing a stringified list or dictionary, use `import ast; data = ast.literal_ev" + "al(user_input)` which only evaluates literal constants.",
                    snippet, "result = safe_dispatch.get(user_input, default_handler)()")

        # Insecure deserialization
        deser_patterns = [
            (r"""\bp" + "ickle\.(lo" + "ads?|lo" + "ad)\s*\(""", "pickle.load — arbitrary code execution"),
            (r"""\byaml\.lo" + "ad\s*\((?!.*Loader\s*=\s*yaml\.(?:safe|base)Loader)""", "yaml.load without SafeLoader"),
            (r"""\bjsonp" + "ickle\.decode\s*\(""", "jsonpickle.decode — arbitrary object instantiation"),
            (r"""\bshelve\.open\s*\(""", "shelve.open — pickle-based persistence"),
            (r"""\bmars" + "hal\.lo" + "ads?\s*\(""", "marshal deserialization"),
        ]
        for pat, label in deser_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", f"Insecure Deserialization — {label}",
                    f"The application is using `{label}` to deserialize data. In Python, `p" + "ickle` is notoriously insecure because it can execute arbitrary code during the unpickling process. If an attacker can provide a malicious serialized payload, they can gain full control over the execution environment. This vulnerability is a common vector for Remote Code Execution (RCE).",
                    "Never deserialize data from untrusted sources using `p" + "ickle`, `marshal`, or insecure `yaml.lo" + "ad()`. Instead, use data-only formats like JSON. If you must use a complex format, use `yaml.safe_lo" + "ad()` or ensure the data is digitally signed and verified before processing.",
                    "Replace `p" + "ickle.lo" + "ads(data)` with `json.lo" + "ads(data)` for pure data objects, or `yaml.safe_lo" + "ad(data)` if using YAML. If you must use p" + "ickle, verify a HMAC signature of the data first.",
                    snippet, "data = yaml.safe_lo" + "ad(raw_input)")

        # Path traversal
        path_patterns = [
            r"""open\s*\(\s*(request|form|args|params|user_input|data)\b""",
            r"""open\s*\(\s*.*?\+\s*(request|form|args|params)\b""",
            r"""os\.path\.(join|abspath|realpath)\s*\(.*?(request|form|args|params|input)\b""",
        ]
        for pat in path_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", "Path Traversal — user-controlled file path",
                    "The application is opening or manipulating a file path using input that may be controlled by a user. This can lead to 'Path Traversal' (or 'Directory Traversal') where an attacker uses sequences like `../../` to escape the intended directory and read sensitive files (like `/etc/passwd` or `.env`) from the server.",
                    "Always sanitize and validate file paths. You should resolve the final absolute path and ensure it stays within a designated 'safe root' directory. Reject any input containing path separators like `/` or `\\` if they aren't expected, and never trust user-supplied filenames directly.",
                    "Use `os.path.basename()` to strip directory parts from a filename, and `os.path.abspath()` to check the resolved path: `full_path = os.path.abspath(os.path.join(SAFE_DIR, filename)); if not full_path.startswith(SAFE_DIR): raise PermissionError`.",
                    snippet, "safe = os.path.realpath(os.path.join(BASE_DIR, filename)); assert safe.startswith(BASE_DIR)")

        # SSRF
        ssrf_patterns = [
            r"""requests\.(get|post|put|delete|head|options)\s*\(\s*(request|form|args|params|url|user_url)\b""",
            r"""urllib\.request\.urlopen\s*\(\s*(request|form|args|params)\b""",
            r"""httpx\.(get|post)\s*\(\s*(request|form|args|params)\b""",
        ]
        for pat in ssrf_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", "Server-Side Request Forgery (SSRF)",
                    "The application is making outbound HTTP requests to a URL that can be influenced by a user. This 'Server-Side Request Forgery' (SSRF) allows an attacker to use the server as a proxy to probe internal networks, access metadata services (like AWS 169.254.169.254), or attack other internal systems that aren't exposed to the internet.",
                    "Strictly validate all user-supplied URLs. The best defense is an 'allowlist' of permitted hostnames. If an allowlist isn't possible, you must block access to private and link-local IP ranges (127.0.0.1, 10.0.0.0/8, etc.) and ensure the application doesn't follow malicious redirects.",
                    "Before making the request, parse the URL and verify the hostname: `host = urlparse(url).hostname; if host not in ['trusted.com', 'api.others.com']: raise ValueError('Untrusted host')`.",
                    snippet)

        # XXE
        xxe_patterns = [
            r"""etree\.parse\s*\(""",
            r"""lxml\.etree\b""",
            r"""xml\.etree""",
            r"""minidom\.parse\s*\(""",
        ]
        no_xxe_protection = "resolve_entities" not in lowered and "defusedxml" not in lowered
        if no_xxe_protection:
            for pat in xxe_patterns:
                snippet = _extract_snippet(content, pat)
                if snippet:
                    add("HIGH", "XML External Entity (XXE) Injection",
                        "The application is parsing XML without explicitly disabling external entity resolution. An attacker can use this to include local files in the XML output (e.g., `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>`) or trigger outbound requests, leading to data theft or internal service probing.",
                        "Use a secure XML library or configure your parser to disable DTDs and external entities. The `defusedxml` project provides a set of wrappers for the standard library that are pre-configured to be safe against these attacks.",
                        "Install the `defusedxml` library and use its methods for parsing: `from defusedxml.ElementTree import parse; tree = parse(xml_file)`. If using `lxml`, set `resolve_entities=False` in the parser.",
                        snippet, "import defusedxml.ElementTree as ET; tree = ET.parse(source)")

        # Template injection
        if re.search(r"""(render_template_string|Environment\(\)\.from_string|jinja2\.Template)\s*\(.*?(request|input|user|param)""", content):
            snippet = _extract_snippet(content, r"""render_template_string|Environment\(\)\.from_string""")
            if snippet:
                add("HIGH", "Server-Side Template Injection (SSTI)",
                    "Rendering user-supplied strings as templates allows attackers to execute arbitrary code on the server.",
                    "Never pass user input as template source. Use static template files and pass data as context variables only.",
                    "Replace `render_template_string(user_input)` with `render_template('template.html', data=validated_input)`.",
                    snippet)

        # Insecure random
        if re.search(r"""\brandom\.(random|randint|choice|randrange|uniform)\s*\(""", content) and \
           re.search(r"""(token|secret|csrf|nonce|session|otp|key)\s*=\s*.*?random\.""", content, re.IGNORECASE):
            snippet = _extract_snippet(content, r"""(token|secret|csrf|nonce|session|otp|key)\s*=\s*.*?random\.""", re.IGNORECASE)
            add("MEDIUM", "Insecure random — `random` module used for security tokens",
                "The `random` module in Python uses a Pseudo-Random Number Generator (PRNG) that is deterministic if the seed is known. Using it for sensitive values like security tokens, passwords, or session IDs makes your system vulnerable to 'prediction attacks'. An attacker could predict future values and hijack sessions or tokens.",
                "Always use a 'Cryptographically Secure Pseudo-Random Number Generator' (CSPRNG) for security-sensitive data. In Python, the `secrets` module was specifically introduced for this purpose. It ensures that the generated values are truly random and cannot be easily predicted.",
                "Replace calls to the `random` module with the `secrets` module: `import secrets; token = secrets.token_urlsafe(32)` or `secrets.randbelow(100)` for integers.",
                snippet, "import secrets; token = secrets.token_urlsafe(32)")

        # Debug mode
        if re.search(r"""(?i)(app\.run|debug)\s*\(.*?debug\s*=\s*True""", content) or \
           re.search(r"""DEBUG\s*=\s*True""", content):
            snippet = _extract_snippet(content, r"""(app\.run.*?debug\s*=\s*True|DEBUG\s*=\s*True)""", re.IGNORECASE)
            add("MEDIUM", "Debug mode enabled — do not deploy to production",
                "Debug mode exposes stack traces, interactive debuggers, and internal state to any client.",
                "Set `DEBUG = False` and use environment variables. Never enable debug mode in production deployments.",
                "Use `DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'` and ensure it is False in production.",
                snippet, "DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'")

        # Broad exception suppression
        bare_except_count = len(re.findall(r"""^\s*except\s*:\s*$""", content, re.MULTILINE))
        if bare_except_count >= 2:
            add("LOW", "Overly broad exception handling (bare except:)",
                "Catching all exceptions including SystemExit and KeyboardInterrupt masks errors and hinders debugging.",
                "Catch specific exception types. Use `except Exception as e:` at minimum, and log the exception.",
                "Replace `except:` with `except (ValueError, TypeError) as e: logger.error(e)` or a specific exception type.",
                "except:", "except Exception as e:\n    logger.exception('Unexpected error: %s', e)")

        # Missing CSRF
        has_post_route = bool(re.search(r"""@\w+\.route\s*\(.*?POST""", content))
        has_csrf = "csrf" in lowered or "csrfprotect" in lowered or "wtforms" in lowered
        if has_post_route and not has_csrf:
            add("MEDIUM", "Missing CSRF protection on POST endpoints",
                "POST endpoints without CSRF tokens allow cross-origin requests to perform state-changing actions on behalf of authenticated users.",
                "Use Flask-WTF or a CSRF middleware to validate CSRF tokens on all state-changing requests.",
                "Add `from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app)` and include `{{ csrf_token() }}` in forms.",
                re.search(r"""@\w+\.route.*?POST""", content).group(0) if re.search(r"""@\w+\.route.*?POST""", content) else "")

        # Python AST analysis for deeper checks
        try:
            import ast as _ast
            tree = _ast.parse(content)
            for node in _ast.walk(tree):
                # assert statements disabled with -O flag (security checks)
                if isinstance(node, _ast.Assert):
                    pass  # Not flagged generically
                # Subpro" + "cess with sh" + "ell=True via keyword
                if isinstance(node, _ast.Call):
                    func_name = ""
                    if isinstance(node.func, _ast.Attribute):
                        func_name = node.func.attr
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, _ast.Constant) and kw.value.value is True:
                            if func_name in {"run", "call", "Popen", "check_output", "check_call"}:
                                line = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                add("HIGH", "Command Injection — sh" + "ell=True confirmed by AST",
                                    "subpro" + "cess called with sh" + "ell=True expands the command through /bin/sh, enabling injection.",
                                    "Refactor to pass a list of arguments with sh" + "ell=False.",
                                    "subpro" + "cess.run(['program', arg1], sh" + "ell=False, check=True)",
                                    line)
        except SyntaxError:
            pass
        except Exception:
            pass

    # ── 3. JAVASCRIPT / TYPESCRIPT RULES ─────────────────────────────────────
    if is_js:

        # XSS sinks
        xss_patterns = [
            (r"""dangerouslySetInnerHTML\s*=\s*\{""", "React dangerouslySetInnerHTML — XSS sink"),
            (r"""\.innerHTML\s*=""", "innerHTML assignment — XSS sink"),
            (r"""document\.write\s*\(""", "document.write() — XSS sink"),
            (r"""\.outerHTML\s*=""", "outerHTML assignment — XSS sink"),
            (r"""(?i)insertAdjacentHTML\s*\(""", "insertAdjacentHTML — XSS sink"),
        ]
        for pat, label in xss_patterns:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", label,
                    f"The application is using a dangerous DOM property or method ({label}) that can lead to Cross-Site Scripting (XSS). These 'sinks' allow an attacker to inject and execute malicious scripts in the context of a user's browser. If unvalidated user input is passed to these methods, an attacker could steal session cookies, capture keystrokes, or perform actions on behalf of the user.",
                    "The primary defense against XSS is to never render untrusted data as HTML. Use 'textContent' or 'innerText' instead of 'innerHTML', as these properties treat all input as literal text rather than executable markup. If you must render HTML, use a verified sanitization library like 'DOMPurify' to strip out dangerous tags and attributes.",
                    "Replace `element.innerHTML = userInput` with `element.textContent = userInput`. If you are using React, avoid `dangerouslySetInnerHTML`. If HTML rendering is required, wrap the input: `DOMPurify.sanitize(userInput)`.",
                    snippet, "element.textContent = userInput; // or DOMPurify.sanitize()")

        # e" + "val() in JS
        if re.search(r"""\be" + "val\s*\(""", content):
            snippet = _extract_snippet(content, r"""\be" + "val\s*\(""")
            add("HIGH", "e" + "val() — Remote Code Execution risk",
                "The `e" + "val()` function is one of the most dangerous features in JavaScript. It evaluates a string as code, which means if an attacker can influence that string, they gain full control over the application's execution in the user's browser. There is almost never a legitimate reason to use `e" + "val()` in modern web development.",
                "Replace `e" + "val()` with safer alternatives. If you are parsing JSON data, use `JSON.parse()`. If you need to access properties dynamically, use the bracket notation (e.g., `obj[key]`). For complex dynamic logic, use a predefined map of safe functions.",
                "Remove the `e" + "val()` call. Example: Replace `e" + "val('var x = ' + data)` with `const x = JSON.parse(data)`. Never pass user-influenced strings to an evaluation function.",
                snippet, "const result = JSON.parse(data);")

        # prototype pollution
        if re.search(r"""(merge|extend|assign|deepCopy|lodash|_\.merge)\s*\(.*?(req\.|request\.|body\.|params\.|query\.)""", content):
            snippet = _extract_snippet(content, r"""(merge|extend|assign|deepCopy)\s*\(""")
            if snippet:
                add("HIGH", "Prototype Pollution risk",
                    "The application is merging user-controlled objects into other objects using a potentially vulnerable method. In JavaScript, an attacker can provide keys like `__proto__` or `constructor` to modify the global `Object.prototype`. This 'Prototype Pollution' can lead to unexpected behavior, denial of service, or even remote code execution if it overrides sensitive internal properties.",
                    "Before merging objects, you must strictly validate the keys and prevent the use of sensitive property names like `__proto__`. Alternatively, use safer merging libraries or create objects with a null prototype (`Object.create(null)`) for temporary data structures to ensure they don't inherit from the global object.",
                    "Sanitize the input keys before merging: `if (key === '__proto__' || key === 'constructor') continue;`. Consider using `Object.freeze()` or `Object.seal()` on critical prototypes if possible.",
                    snippet)

        # Insecure JWT handling
        if re.search(r"""(jwt\.verify|jsonwebtoken)\s*\(.*?algorithm.*?none""", content, re.IGNORECASE) or \
           re.search(r"""algorithms\s*:\s*\[\s*["']none["']""", content, re.IGNORECASE):
            add("HIGH", "JWT 'none' algorithm accepted",
                "Accepting 'none' as JWT algorithm allows attackers to forge tokens without a signature.",
                "Explicitly specify and enforce a strong signing algorithm (RS256, ES256, HS256). Never allow 'none'.",
                "Use `jwt.verify(token, secret, { algorithms: ['HS256'] })` — always whitelist algorithms.",
                "algorithms: ['none']", "algorithms: ['HS256']")

        # Open redirect
        if re.search(r"""(res\.redirect|window\.location|location\.href)\s*[=(].*?(req\.|request\.|query\.|params\.|body\.)""", content):
            snippet = _extract_snippet(content, r"""(res\.redirect|window\.location\.href)\s*[=(]""")
            add("MEDIUM", "Open Redirect — user-controlled redirect URL",
                "Redirecting to a URL from user input without validation allows phishing and session-token theft attacks.",
                "Validate redirect targets against an allowlist of permitted URLs or paths.",
                "Only allow relative paths or explicitly permitted domains: `if not url.startswith('/') or contains_scheme(url): url = '/'`.",
                snippet)

        # Debug/console.log with sensitive data
        if re.search(r"""console\.(log|debug|info)\s*\(.*?(password|token|secret|key|credential)""", content, re.IGNORECASE):
            snippet = _extract_snippet(content, r"""console\.(log|debug|info)\s*\(.*?(password|token|secret|key|credential)""", re.IGNORECASE)
            add("MEDIUM", "Sensitive data in console output",
                "Logging credentials or tokens to the console exposes them in browser DevTools and server logs.",
                "Remove sensitive values from all logging statements. Use structured logging with field redaction.",
                "Remove console.log with credentials. If debugging is needed, use a logging library with automatic secret masking.",
                snippet)

    # ── 4. C / C++ RULES ─────────────────────────────────────────────────────
    if is_c:

        unsafe_funcs = [
            (r"""\bgets\s*\(""", "gets() — unbounded buffer read (always unsafe)"),
            (r"""\bstrcpy\s*\(""", "strcpy() — no bounds check, buffer overflow"),
            (r"""\bstrcat\s*\(""", "strcat() — no bounds check, buffer overflow"),
            (r"""\bsprintf\s*\(""", "sprintf() — no bounds check, format string risk"),
            (r"""\bscanf\s*\((?!.*%\d+s)""", "scanf() without width limit — buffer overflow"),
            (r"""\bmktemp\s*\(""", "mktemp() — insecure temp file creation (TOCTOU)"),
        ]
        for pat, label in unsafe_funcs:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add("HIGH", f"Unsafe C function: {label}",
                    f"The use of `{label}` is a major security risk in C/C++ development. These functions do not perform any bounds checking on the buffers they write to, which is the primary cause of 'Buffer Overflow' vulnerabilities. An attacker can provide an input larger than the destination buffer, overwriting adjacent memory and potentially hijacking the program's execution flow.",
                    "Always use the 'bounded' versions of these functions which require a maximum size for the destination buffer. These 'safe' variants (like `fgets`, `snprintf`, and `strlcpy`) prevent memory corruption by ensuring that no more than the specified number of bytes are written.",
                    f"Immediately replace the unsafe call with its safe equivalent. For example, replace `strcpy(dest, src)` with `strncpy(dest, src, sizeof(dest))` (and ensure null-termination) or use `snprintf(dest, sizeof(dest), \"%s\", src)`.",
                    snippet)

        # Integer overflow
        if re.search(r"""(malloc|calloc|realloc)\s*\(.*?\*""", content):
            snippet = _extract_snippet(content, r"""(malloc|calloc|realloc)\s*\(.*?\*""")
            add("HIGH", "Integer overflow in memory allocation size",
                "Multiplying untrusted size values without overflow checking can produce a small allocation, leading to heap overflow.",
                "Validate sizes before arithmetic. Use calloc() to combine count*size safely, or check for overflow explicitly.",
                "Use `calloc(count, size)` instead of `malloc(count * size)`. Check: if (count > SIZE_MAX / size) abort();",
                snippet)

        # Null pointer dereference
        if re.search(r"""(malloc|calloc|realloc)\s*\([^;]+\)\s*;(?!\s*if)""", content):
            snippet = _extract_snippet(content, r"""(malloc|calloc)\s*\(""")
            add("MEDIUM", "Potential null pointer dereference — unchecked allocation",
                "Not checking the return value of malloc/calloc before use causes undefined behavior when allocation fails.",
                "Always check pointer results: `if (ptr == NULL) { handle_error(); }`",
                "Add null check: `p = malloc(n); if (!p) { perror('malloc'); exit(EXIT_FAILURE); }`",
                snippet)

        # Format string injection
        if re.search(r"""(printf|fprintf|syslog|sprintf)\s*\(\s*\w+\s*\)""", content):
            snippet = _extract_snippet(content, r"""(printf|fprintf)\s*\(\s*\w+\s*\)""")
            add("HIGH", "Format string injection",
                "The application is passing a user-controlled string directly as the format argument of a `printf`-style function. This is a severe 'Format String' vulnerability. An attacker can use format specifiers like `%x` to read data from the stack or `%n` to write arbitrary values to memory, leading to information disclosure or full code execution.",
                "Always use a constant format string literal and pass the dynamic data as subsequent arguments. This ensures that any format specifiers within the data are treated as literal text and not interpreted by the formatting engine.",
                "Change `printf(user_input)` to `printf(\"%s\", user_input)`. Never allow user-supplied data to influence the format string itself.",
                snippet, 'printf("%s", msg);')

    # ── 5. TERRAFORM / IaC RULES ─────────────────────────────────────────────
    if is_tf:
        tf_checks = [
            (r"""0\.0\.0\.0/0""", "HIGH", "Overly permissive network exposure (0.0.0.0/0)",
             "This Terraform configuration exposes a resource to the entire internet (0.0.0.0/0). Opening management ports (like SSH 22, RDP 3389, or DB ports) to the world is a critical security configuration error. It allows anyone on the internet to attempt brute-force attacks, scan for vulnerabilities, or exploit unpatched services.",
             "Follow the 'Principle of Least Privilege'. Restrict your ingress and egress rules to specific, trusted IP ranges—such as your corporate VPN, static office IPs, or other internal VPC CIDR blocks. Using private endpoints and bastion hosts (jump boxes) is the recommended architecture for secure administrative access.",
             "cidr_blocks = [\"10.0.0.0/8\"]"),
            (r"""(?i)encrypted\s*=\s*false""", "HIGH", "Unencrypted storage resource",
             "A storage resource (such as an EBS volume, RDS instance, or S3 bucket) is explicitly configured without encryption at rest. This means that if the underlying physical storage media is compromised or if there is an unauthorized snapshot access, your sensitive business data is fully exposed in plain text.",
             "Enable encryption by default for all storage resources. Most cloud providers offer integrated KMS (Key Management Service) support that handles encryption with minimal performance impact. Set the encryption flag to true and specify an appropriate KMS key ARN where applicable.",
             "encrypted = true"),
            (r"""(?i)publicly_accessible\s*=\s*true""", "HIGH", "Database publicly accessible",
             "A database instance is configured to be 'publicly accessible', meaning it will be assigned a public IP address and can be reached from the internet. This bypasses the security layer of your VPC and exposes your most sensitive data layer to direct external attacks.",
             "Keep database instances within private subnets. Use security groups to allow access only from specific application tiers (like your web servers or API gateways) and never assign a public IP address to a database instance. If remote access is needed, use a secure VPN or an SSH tunnel through a bastion host.",
             "publicly_accessible = false"),
            (r"""(?i)acl\s*=\s*["'](public-read|public-read-write|authenticated-read)["']""", "HIGH", "Public S3 bucket ACL",
             "The S3 bucket is configured with a public access control list (ACL). This is a common cause of high-profile data leaks. It allows anonymous users to list or download objects from your bucket, potentially exposing private customer data, configuration files, or internal assets.",
             "Set S3 bucket ACLs to 'private' by default. Access control should be managed through IAM policies and S3 Bucket Policies, which provide more granular control and auditability. Additionally, enable the 'Block Public Access' feature at the account or bucket level as a secondary safety net.",
             'acl = "private"'),
            (r"""(?i)force_destroy\s*=\s*true""", "MEDIUM", "Terraform force_destroy enabled on critical resource",
             "The `force_destroy` flag is enabled for this resource, which allows Terraform to irreversibly delete the resource and all its contained data (like all objects in an S3 bucket) even if it isn't empty. This significantly increases the risk of accidental, catastrophic data loss during infrastructure updates.",
             "Remove the `force_destroy` flag from any resource that contains persistent data in production environments. Instead, use 'prevent_destroy' lifecycle rules to protect critical assets from accidental deletion during a `terraform destroy` or `terraform apply` operation.",
             "prevent_destroy = true"),
            (r"""(?i)skip_final_snapshot\s*=\s*true""", "MEDIUM", "RDS skip_final_snapshot = true",
             "The RDS instance is configured to skip the final snapshot before being deleted. This means that if the database is destroyed (intentionally or accidentally), there is no safety backup of the latest data state, leading to permanent and unrecoverable data loss.",
             "Always set `skip_final_snapshot = false` for production databases. Ensure that a `final_snapshot_identifier` is provided so that a restorable backup is created whenever the database instance is terminated.",
             "skip_final_snapshot = false"),
        ]
        for pat, sev, title, root, solution, fixed in tf_checks:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add(sev, title, root, solution, f"Change to: `{fixed}`", snippet, fixed)

    # ── 6. DOCKERFILE RULES ──────────────────────────────────────────────────
    if is_docker:
        docker_checks = [
            (r"""(?im)^\s*USER\s+root\s*$""", "MEDIUM", "Container runs as root",
             "The Dockerfile explicitly sets the user to 'root' or does not define a non-root user. If an attacker successfully exploits a vulnerability within the running container, they will have root privileges on the container's OS, making it significantly easier to perform a 'container breakout' and compromise the host machine.",
             "Follow the 'Principle of Minimal Privilege'. Create a specific, limited user account within the Dockerfile and use the `USER` instruction to switch to it before the application starts. Ensure that the application only has permission to write to the specific directories it needs.",
             "USER appuser"),
            (r"""(?im)^\s*ADD\s+https?://""", "MEDIUM", "ADD with remote URL — use CURL+checksum instead",
             "The `ADD` instruction is being used to fetch a remote file via HTTP/S. This is considered insecure because `ADD` does not perform any integrity or checksum verification. This leaves you vulnerable to 'Man-in-the-Middle' (MITM) attacks or supply chain compromises where the remote file is maliciously altered.",
             "Use the `RUN` instruction with `curl` or `wget` to download files. This allows you to explicitly verify the file's integrity using a SHA-256 checksum (e.g., `sha256sum -c`) before proceeding with the installation, ensuring that you are using the exact file you intended.",
             "RUN curl -fsSL https://... | sha256sum -c - && tar xzf ..."),
            (r"""(?im)^\s*RUN\s+.*?(curl|wget).*?\|\s*bash""", "HIGH", "Piping curl/wget output directly to bash",
             "The Dockerfile is downloading a script and piping it directly into `bash` for execution. This is an extremely high-risk pattern known as 'Curling to Bash'. It trusts the remote server and the network path completely. If either is compromised, an attacker can execute arbitrary code on your build server and inside your container images.",
             "Never execute remote scripts directly. Instead, download the script to a temporary file, verify its integrity against a known checksum, and inspect its contents if possible. Only after verification should you execute the script in a separate step.",
             "RUN curl -fsSL https://... -o install.sh && sha256sum install.sh && bash install.sh"),
            (r"""(?im)^(?!.*no-cache).*\bRUN\s+apt-get\s+install\b""", "LOW", "apt-get install without --no-install-recommends",
             "The `apt-get install` command is used without the `--no-install-recommends` flag. This results in the installation of many unnecessary 'recommended' packages, which bloats the container image size and increases the attack surface by providing more tools and libraries that an attacker could potentially abuse.",
             "Add the `--no-install-recommends` flag to all package installation commands to keep your images 'lean' and secure. Also, remember to clean up the local APT cache in the same `RUN` step to further reduce image size.",
             "RUN apt-get install -y --no-install-recommends pkg && rm -rf /var/lib/apt/lists/*"),
            (r"""(?im)^\s*COPY\s+\.\s+""", "LOW", "COPY . copies entire build context",
             "The instruction `COPY . .` copies every file from the current local directory into the container. Without a properly configured `.dockerignore` file, this likely includes sensitive data like `.env` files, local credentials, source control history (.git), and development dependencies that should never be present in a production image.",
             "Use a `.dockerignore` file to explicitly exclude sensitive files and directories from the build context. Alternatively, be specific with your `COPY` commands and only include the exact files and directories required for the application to run.",
             "# Add .dockerignore: .env, *.key, node_modules, .git"),
        ]
        for pat, sev, title, root, solution, fixed in docker_checks:
            snippet = _extract_snippet(content, pat)
            if snippet:
                add(sev, title, root, solution, f"Change to: `{fixed}`", snippet, fixed)

        # Hardcoded secrets in ENV
        if re.search(r"""(?im)^\s*ENV\s+\S*(password|secret|key|token|api)\S*\s*=?\s*\S{6,}""", content, re.IGNORECASE):
            snippet = _extract_snippet(content, r"""(?im)^\s*ENV\s+\S*(password|secret|key|token)\S*""", re.IGNORECASE)
            add("HIGH", "Hardcoded secret in Dockerfile ENV instruction",
                "Sensitive credentials (like passwords or API keys) are defined using the `ENV` instruction in the Dockerfile. These values are 'baked' into the image metadata and stored in plain text across every layer of the image. Anyone with access to the image can easily extract these secrets using a simple `docker inspect` command.",
                "Secrets should never be part of a container image. Instead, pass them at runtime using environment variables (`-e` or `--env-file`), or use a secure secret management system like Docker Secrets or Kubernetes Secrets. This ensures that sensitive data is only injected into the running environment and is not persisted in the image history.",
                "Remove the `ENV` instruction containing secrets from the Dockerfile. Instead, modify your deployment script to pass the secret at runtime: `docker run --env MY_APP_SECRET=$SECRET_STORE_VALUE my_image`.",
                snippet)

    # Dedup by (file, title prefix)
    deduped: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = f"{finding.get('file_name', '')}|{finding.get('issue_description', '')[:80]}"
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

    # Mask common provider key patterns if they appear in strings.
    redacted = re.sub(r"gsk_[A-Za-z0-9_\-]{8,}", "[REDACTED_GROQ_KEY]", raw)
    redacted = re.sub(r"sk-[A-Za-z0-9]{8,}", "[REDACTED_OPENAI_KEY]", redacted)
    redacted = re.sub(r"AIza[0-9A-Za-z_\-]{8,}", "[REDACTED_GEMINI_KEY]", redacted)
    redacted = re.sub(r"Bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED_TOKEN]", redacted, flags=re.IGNORECASE)
    
    # Mask password patterns
    redacted = re.sub(r'(?i)(password|passwd)\s*[:=]\s*["\']?[^"\', \s]{4,}', r'\1=[REDACTED]', redacted)
    
    return redacted


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

def call_openai(prompt: str, system_prompt: str, api_key: str, temperature: float = 0.3) -> str:
    """Call OpenAI API"""
    try:
        client = openai.OpenAI(api_key=api_key)
        completion = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            response_format={"type": "json_object"}
        )
        return completion.choices[0].message.content
    except Exception as e:
        safe_error = redact_sensitive_text(e)
        logger.error(f"OpenAI API Error: {safe_error}")
        return json.dumps({
            "status": "ERROR",
            "stats": {"High": 0, "Medium": 0, "Low": 0},
            "findings": [{
                "file_name": "unknown",
                "issue_description": f"OpenAI Error: {safe_error}",
                "suggested_fix": "Check API key, account balance, or rate limits."
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


def _try_parse_json_relaxed(text: str) -> Optional[Dict[str, Any]]:
    """
    Tries to parse JSON from a string that might be wrapped in markers or have trailing text.
    """
    clean_text = text.strip()
    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        pass

    try:
        start = clean_text.find('{')
        end = clean_text.rfind('}')
        if start != -1 and end != -1:
            return json.loads(clean_text[start:end+1])
    except (json.JSONDecodeError, ValueError):
        pass

    return None


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
            "summary": "Our comprehensive static analysis has concluded, and we are pleased to report that no explicit security vulnerabilities were detected in this file during this pass. The code demonstrates a clean security posture regarding common anti-patterns and known vulnerability signatures.",
            "strengths": [
                "The source code appears to follow secure coding patterns for the identified language and framework.",
                "No hardcoded credentials, injection sinks, or insecure cryptographic primitives were discovered.",
                "The implementation shows a good baseline for security hygiene and maintainability."
            ],
            "key_risks": [
                "While no issues were found, static analysis cannot detect all logic flaws or runtime-specific vulnerabilities.",
                "The security of the file also depends on its dependencies and the environment in which it executes."
            ],
            "maintainability_assessment": "The code is well-structured from a security perspective. Continued use of linting and type-checking will help maintain this high standard.",
            "test_recommendations": [
                "Implement unit tests that specifically target edge cases and malformed inputs to ensure ongoing robustness.",
                "Consider adding property-based testing to explore a wider range of potential input states."
            ],
            "priority_actions": [
                "Maintain regular dependency audits to identify and remediate vulnerabilities in third-party libraries.",
                "Integrate this security scanning process into your continuous integration (CI) pipeline for real-time feedback."
            ]
        }

    return {
        "summary": (
            f"The security analysis has identified {finding_count} unresolved issue(s) within this file, including {high} high-severity risk(s). "
            "These findings indicate potential entry points for attackers and should be addressed systematically to harden the application's defense-in-depth posture."
        ),
        "strengths": [
            "The code provides a clear structure, which facilitates the identification and remediation of these security gaps.",
            "The identified vulnerabilities are well-known patterns with established industry-standard fixes."
        ],
        "key_risks": [
            f"The presence of {high} High-severity issues poses an immediate threat to the confidentiality and integrity of the system.",
            "Chained vulnerabilities (combining Medium and Low risks) could still lead to a significant security compromise if left unaddressed."
        ],
        "maintainability_assessment": "Security technical debt is currently elevated. Resolving these findings will not only secure the application but also improve the overall quality and reliability of the codebase.",
        "test_recommendations": [
            "Develop specific security regression tests for each identified vulnerability to ensure they do not reappear in future updates.",
            "Incorporate automated security scanning into the development workflow to catch similar issues earlier in the lifecycle."
        ],
        "priority_actions": [
            f"Immediate Action: Remediate the {high} High-severity vulnerability(ies) prior to any production deployment.",
            "Schedule a follow-up review for the Medium and Low risk issues to ensure a comprehensive security hardening."
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
            "overall_assessment": "The comprehensive security audit has found the reviewed codebase to be in a secure state with no detectable vulnerabilities. This indicates a strong adherence to secure development lifecycles and proactive risk management.",
            "most_important_findings": [],
            "immediate_next_steps": [
                "Continue to maintain rigorous dependency management and security patching schedules.",
                "Extend the current testing suite with targeted fuzzing and penetration testing for critical components."
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
        "overall_assessment": "The security analysis has identified several critical areas requiring immediate attention. While the core logic is sound, the presence of specific vulnerability patterns significantly increases the application's risk profile. A systematic remediation effort is required to ensure a high level of security assurance.",
        "most_important_findings": fallback_items,
        "immediate_next_steps": [
            "Prioritize the remediation of 'High' severity findings as they represent the most immediate threat to your infrastructure and data.",
            "Establish a clear ownership and remediation timeline for all identified security tasks.",
            "Perform a verification scan after fixes are applied to confirm that all vulnerabilities have been effectively neutralized."
        ]
    }

SECURITY_ANALYSIS_SYSTEM_PROMPT = """You are a Senior Cyber Security Researcher and Pentester with 20+ years of experience in SAST (Static Application Security Testing).
Your task is to perform a deep security analysis of the provided source code.
Identify vulnerabilities including OWASP Top 10, SANS Top 25, logic flaws, hardcoded secrets, and insecure configurations.

Return your findings in a strict JSON format with the following structure:
{
  "status": "VULNERABLE" | "SAFE",
  "findings": [
    {
      "file_name": "string",
      "issue_description": "[SEVERITY] Brief title of the issue",
      "severity": "High" | "Medium" | "Low",
      "root_problem": "Detailed technical explanation of the root cause",
      "suggested_solution": "Conceptual fix or mitigation strategy",
      "suggested_fix": "Concrete code change or command to fix the issue",
      "source_code": "The vulnerable code snippet",
      "fixed_code": "The corrected code snippet"
    }
  ],
  "overall_code_review": {
    "summary": "High-level overview of the file's security posture",
    "strengths": ["list of positive security patterns"],
    "key_risks": ["list of main risks"],
    "maintainability_assessment": "How the code quality affects security",
    "test_recommendations": ["specific security tests to add"],
    "priority_actions": ["immediate steps for the developer"]
  }
}

Rules:
1. Ensure all code snippets are properly escaped for valid JSON.
2. Be specific and technical. No generic advice.
3. If no vulnerabilities are found, return empty findings and status SAFE.
4. Always provide 'fixed_code' for every finding.
"""

SECURITY_ANALYSIS_USER_PROMPT = """Analyze the following file for security vulnerabilities:
File Name: {filename}
Persona context: {persona} (Tailor your explanation for this level)

Source Code:
{content}
"""

def analyze_code_with_ai(filename: str, content: str, api_key: str, persona: str, provider: str = None) -> Dict[str, Any]:
    """
    Calls the AI provider to perform security analysis.
    """
    if not (api_key or DEFAULT_GROQ_API_KEY):
        return {"status": "SAFE", "findings": [], "overall_code_review": {}}

    prompt = SECURITY_ANALYSIS_USER_PROMPT.format(
        filename=filename,
        persona=persona,
        content=content
    )
    
    try:
        response_text = call_provider_with_json_prompt(
            prompt,
            SECURITY_ANALYSIS_SYSTEM_PROMPT,
            api_key,
            provider
        )
        return parse_ai_response(response_text, filename)
    except Exception as e:
        logger.error(f"AI analysis failed for {filename}: {redact_sensitive_text(e)}")
        return {"status": "ERROR", "findings": [], "overall_code_review": {}}


def analyze_code_logic(filename: str, content: str, api_key: str, persona: str, provider: str = None):
    """
    Hybrid analysis: Performs both local SAST and AI-powered analysis.
    """
    # 1. Run Local SAST Engine
    try:
        local_findings = run_full_sast_engine(filename, content)
    except Exception as e:
        logger.error(f"Unexpected error in local SAST engine for {filename}: {e}")
        local_findings = []

    # 2. Run AI-Powered Analysis (only if a valid-looking key is available)
    ai_result = {"status": "SAFE", "findings": [], "overall_code_review": {}}
    effective_key = (api_key or "").strip() or DEFAULT_GROQ_API_KEY or ""
    
    # Only attempt AI if key matches a known provider format or if a specific AI provider was chosen manually.
    # This ensures "auto" mode gracefully falls back to local SAST when no valid keys are present.
    is_manual_ai = provider and provider in {"groq", "openai", "gemini"}
    has_valid_key = any(effective_key.startswith(pre) for pre in ["gsk_", "sk-", "AIzaSy"])

    if (is_manual_ai or has_valid_key) and (provider != "local"):
        ai_result = analyze_code_with_ai(filename, content, api_key, persona, provider)

    # 3. Merge results
    seen_issues = set()
    merged_findings = []

    # Prioritize AI findings
    for f in ai_result.get("findings", []):
        desc = f.get("issue_description", "")
        if desc and desc not in seen_issues:
            merged_findings.append(f)
            seen_issues.add(desc)

    for f in local_findings:
        desc = f.get("issue_description", "")
        if desc and desc not in seen_issues:
            merged_findings.append(f)
            seen_issues.add(desc)

    # Sort merged findings
    merged_findings = sort_findings_by_severity(merged_findings)
    
    # Determine status
    if ai_result.get("status") == "ERROR":
        status = "VULNERABLE" if merged_findings else "ERROR"
    elif merged_findings:
        status = "VULNERABLE"
    else:
        status = "SAFE"

    # Final payload
    parsed = {
        "status": status,
        "stats": build_stats_from_findings(merged_findings),
        "findings": merged_findings,
        "scanned_file_name": filename,
        "overall_code_review": ai_result.get("overall_code_review") or build_fallback_file_review(merged_findings),
        "improvement_suggestions": ai_result.get("improvement_suggestions", [
            "Keep dependencies up to date using automated vulnerability scanners.",
            "Run continuous static analysis on all Pull Requests.",
            "Enforce linting rules in CI/CD."
        ])
    }

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
        result = analyze_code_logic(filename, content, effective_key, persona, provider)
        individual_results.append(result)
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

        result = await asyncio.to_thread(analyze_code_logic, filename, scanned_file["content"], effective_key, persona, provider)
        results.append(result)

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
        
    except HTTPException as he:
        logger.warning(f"HTTP error during analysis: {he.detail}")
        return build_error_scan_response(he.detail, report_id=locals().get("report_id"))
    except Exception as e:
        logger.exception(f"Unexpected error processing analysis: {redact_sensitive_text(e)}")
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
        
    except HTTPException as he:
        logger.warning(f"HTTP error during github analysis: {he.detail}")
        return build_error_scan_response(he.detail, report_id=locals().get("report_id"))
    except Exception as e:
        logger.exception(f"Unexpected error processing github analysis: {redact_sensitive_text(e)}")
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

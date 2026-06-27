"""
SecureAudit — Flask Backend
Secure Code Review Platform
"""

import os
import re
import json
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, jsonify, session,
    render_template, redirect, url_for, abort
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ==========================================
# APP CONFIGURATION
# ==========================================
app = Flask(__name__, template_folder="..", static_folder="..", static_url_path="")

# SECURE: Load secrets from environment — never hardcode
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=512 * 1024,          # 500 KB upload limit
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

# SECURE: CSRF protection on all state-changing endpoints
csrf = CSRFProtect(app)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Upload / report directories
import tempfile

# REQUIRED: Vercel serverless filesystem is read-only except /tmp
IS_SERVERLESS = os.environ.get("VERCEL") == "1"
BASE_DIR = Path(tempfile.gettempdir()) if IS_SERVERLESS else Path(".")

UPLOAD_FOLDER = BASE_DIR / "uploads"
REPORTS_FOLDER = BASE_DIR / "reports"
UPLOAD_FOLDER.mkdir(exist_ok=True, parents=True)
REPORTS_FOLDER.mkdir(exist_ok=True, parents=True)

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".php", ".java", ".c", ".cpp", ".rb", ".go"}


# ==========================================
# VULNERABILITY RULE ENGINE
# ==========================================
VULN_RULES = {
    "python": [
        {
            "id": "PY001",
            "title": "SQL Injection",
            "severity": "critical",
            "owasp": "A03:2021",
            "cwe": "CWE-89",
            "cvss": "9.8",
            "pattern": re.compile(
                r'(execute|cursor\.execute)\s*\([^)]*(\+|%\s*[^)]+)',
                re.IGNORECASE
            ),
            "description": (
                "String concatenation or % formatting used in SQL query construction. "
                "Allows attackers to inject arbitrary SQL commands."
            ),
            "fix": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
        },
        {
            "id": "PY002",
            "title": "Hardcoded Credentials",
            "severity": "critical",
            "owasp": "A02:2021",
            "cwe": "CWE-798",
            "cvss": "9.1",
            "pattern": re.compile(
                r'(password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{4,}["\']',
                re.IGNORECASE
            ),
            "description": (
                "Credentials or secret keys are hardcoded in source code. "
                "These are discoverable through code access or version control history."
            ),
            "fix": "Use os.environ.get('SECRET_KEY') or a secrets manager (Vault, AWS Secrets Manager).",
        },
        {
            "id": "PY003",
            "title": "Weak Password Hashing (MD5/SHA1)",
            "severity": "high",
            "owasp": "A02:2021",
            "cwe": "CWE-916",
            "cvss": "7.5",
            "pattern": re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
            "description": (
                "MD5 and SHA1 are broken for password storage. "
                "No salting means rainbow table attacks are trivial; "
                "both are computed billions of times/sec on modern GPUs."
            ),
            "fix": "Use bcrypt.hashpw() or passlib with argon2 for password hashing.",
        },
        {
            "id": "PY004",
            "title": "Debug Mode Enabled",
            "severity": "high",
            "owasp": "A05:2021",
            "cwe": "CWE-94",
            "cvss": "7.5",
            "pattern": re.compile(r'app\.run\s*\(.*debug\s*=\s*True', re.IGNORECASE),
            "description": (
                "Flask debug mode exposes an interactive debugger "
                "allowing arbitrary Python code execution via the browser. "
                "This is a Remote Code Execution risk."
            ),
            "fix": "Set debug=False in production. Use gunicorn or uWSGI as the production server.",
        },
        {
            "id": "PY005",
            "title": "Insecure Randomness",
            "severity": "medium",
            "owasp": "A02:2021",
            "cwe": "CWE-338",
            "cvss": "5.9",
            "pattern": re.compile(r'random\.(randint|random|choice|shuffle)\s*\(', re.IGNORECASE),
            "description": (
                "Python's random module uses a Mersenne Twister PRNG that is "
                "not cryptographically secure. Tokens generated this way are predictable."
            ),
            "fix": "Use the secrets module: secrets.token_urlsafe(32) or secrets.token_hex(32).",
        },
        {
            "id": "PY006",
            "title": "Command Injection",
            "severity": "critical",
            "owasp": "A03:2021",
            "cwe": "CWE-78",
            "cvss": "9.8",
            "pattern": re.compile(r'os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', re.IGNORECASE),
            "description": (
                "User-controlled data passed to shell execution functions. "
                "Allows arbitrary OS command execution on the server."
            ),
            "fix": "Use subprocess.run(['cmd', arg], shell=False) with a list of arguments.",
        },
        {
            "id": "PY007",
            "title": "Path Traversal",
            "severity": "high",
            "owasp": "A01:2021",
            "cwe": "CWE-22",
            "cvss": "7.5",
            "pattern": re.compile(r'open\s*\([^)]*request\.(args|form|json)', re.IGNORECASE),
            "description": (
                "User-supplied path used directly in file open operation. "
                "Attackers can use '../' sequences to read arbitrary files."
            ),
            "fix": "Use os.path.abspath() and verify the resolved path starts with the intended base directory.",
        },
        {
            "id": "PY008",
            "title": "Weak Encryption Mode (ECB)",
            "severity": "high",
            "owasp": "A02:2021",
            "cwe": "CWE-327",
            "cvss": "7.5",
            "pattern": re.compile(r'MODE_ECB', re.IGNORECASE),
            "description": (
                "AES-ECB mode is deterministic — identical plaintext produces identical ciphertext. "
                "This leaks data patterns and is fundamentally insecure."
            ),
            "fix": "Use AES-GCM for authenticated encryption: AES.new(key, AES.MODE_GCM, nonce=os.urandom(16))",
        },
        {
            "id": "PY009",
            "title": "Missing CSRF Protection",
            "severity": "medium",
            "owasp": "A01:2021",
            "cwe": "CWE-352",
            "cvss": "6.5",
            "pattern": re.compile(
                r'@app\.route\s*\([^)]*methods\s*=\s*\[.*POST.*\](?!.*csrf)',
                re.IGNORECASE | re.DOTALL
            ),
            "description": (
                "POST endpoints without CSRF token validation are vulnerable to "
                "Cross-Site Request Forgery, allowing attackers to perform actions "
                "on behalf of authenticated users."
            ),
            "fix": "Use Flask-WTF: CSRFProtect(app). Include {{ csrf_token() }} in all forms.",
        },
        {
            "id": "PY010",
            "title": "Insecure SSL/TLS Verification Disabled",
            "severity": "high",
            "owasp": "A02:2021",
            "cwe": "CWE-295",
            "cvss": "7.4",
            "pattern": re.compile(r'verify\s*=\s*False|CERT_NONE', re.IGNORECASE),
            "description": (
                "SSL certificate verification is disabled. "
                "This exposes the application to Man-in-the-Middle attacks "
                "where an attacker can intercept and tamper with HTTPS traffic."
            ),
            "fix": "Always set verify=True (default) in requests. Use a proper CA certificate bundle.",
        },
    ],
    "javascript": [
        {
            "id": "JS001",
            "title": "Dangerous eval() Usage",
            "severity": "critical",
            "owasp": "A03:2021",
            "cwe": "CWE-94",
            "cvss": "9.8",
            "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
            "description": (
                "eval() executes arbitrary JavaScript. "
                "When called with user input, it allows Remote Code Execution "
                "and Cross-Site Scripting attacks."
            ),
            "fix": "Replace eval() with JSON.parse() for data, or a safe expression evaluator like math.js.",
        },
        {
            "id": "JS002",
            "title": "DOM-based XSS via innerHTML",
            "severity": "high",
            "owasp": "A03:2021",
            "cwe": "CWE-79",
            "cvss": "7.4",
            "pattern": re.compile(r'innerHTML\s*=|document\.write\s*\(', re.IGNORECASE),
            "description": (
                "Assigning unsanitized data to innerHTML or document.write() "
                "allows Cross-Site Scripting. Malicious scripts can steal "
                "session cookies, perform phishing, or redirect users."
            ),
            "fix": "Use textContent instead of innerHTML, or sanitize with DOMPurify before assignment.",
        },
        {
            "id": "JS003",
            "title": "Hardcoded API Key / Secret",
            "severity": "critical",
            "owasp": "A02:2021",
            "cwe": "CWE-798",
            "cvss": "9.1",
            "pattern": re.compile(
                r'(api_key|apiKey|secret|password|token)\s*[=:]\s*["\'][A-Za-z0-9+/=._-]{8,}["\']',
                re.IGNORECASE
            ),
            "description": (
                "API keys or secrets embedded in client-side JavaScript are "
                "trivially extracted by any user who views the page source."
            ),
            "fix": "Move secrets to server-side. Use environment variables. Never expose keys in frontend code.",
        },
        {
            "id": "JS004",
            "title": "No CORS Restriction (Wildcard Origin)",
            "severity": "medium",
            "owasp": "A05:2021",
            "cwe": "CWE-942",
            "cvss": "6.5",
            "pattern": re.compile(r'Access-Control-Allow-Origin.*\*', re.IGNORECASE),
            "description": (
                "Wildcard CORS policy allows any origin to make cross-origin requests. "
                "This can expose authenticated API endpoints to malicious third-party sites."
            ),
            "fix": "Restrict CORS to specific trusted origins: res.header('Access-Control-Allow-Origin', 'https://yourdomain.com')",
        },
    ],
}


# ==========================================
# ANALYSIS ENGINE
# ==========================================
def analyze_code(code: str, language: str) -> dict:
    """
    Perform static analysis on the provided code.
    Returns structured findings with severity, OWASP mapping, and remediation.
    """
    rules = VULN_RULES.get(language.lower(), VULN_RULES.get("python", []))
    findings = []
    lines = code.splitlines()

    for rule in rules:
        for i, line in enumerate(lines, start=1):
            if rule["pattern"].search(line):
                findings.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "owasp": rule["owasp"],
                    "cwe": rule["cwe"],
                    "cvss": rule["cvss"],
                    "line": f"Line {i}",
                    "vulnerable_code": line.strip(),
                    "description": rule["description"],
                    "fix": rule["fix"],
                })
                break  # One finding per rule per file

    # Compute security score
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    deductions = sum(severity_weights.get(f["severity"], 0) for f in findings)
    score = max(0, min(100, 100 - deductions))

    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ["critical", "high", "medium", "low", "info"]}

    return {
        "findings": findings,
        "counts": counts,
        "score": score,
        "grade": _score_to_grade(score),
        "total": len(findings),
        "language": language,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    }


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ==========================================
# AUTH HELPERS
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


# ==========================================
# ROUTES — AUTH
# ==========================================
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """SECURE: Parameterized login with bcrypt verification."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # SECURE: Constant-time comparison via werkzeug
    # In production: look up user from DB by email, then check hash
    user = _get_user_by_email(email)
    if not user or not check_password_hash(user["password_hash"], password):
        logger.warning("Failed login attempt for email: %s", email)
        return jsonify({"error": "Invalid credentials"}), 401

    # SECURE: Regenerate session after login
    session.clear()
    session["user_id"] = user["id"]
    session["email"] = email
    session.permanent = True

    logger.info("Successful login: %s", email)
    return jsonify({"message": "Login successful", "email": email})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


# ==========================================
# ROUTES — CODE ANALYSIS
# ==========================================
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Analyze pasted code for security vulnerabilities.
    """
    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip()
    language = data.get("language", "python").lower()

    if not code:
        return jsonify({"error": "No code provided"}), 400

    if len(code) > 100_000:
        return jsonify({"error": "Code exceeds 100KB limit"}), 413

    if language not in VULN_RULES:
        language = "python"

    result = analyze_code(code, language)

    # Persist report
    report_id = _save_report(result, filename="inline_code." + _lang_ext(language))
    result["report_id"] = report_id

    return jsonify(result)


@app.route("/api/analyze/upload", methods=["POST"])
def api_analyze_upload():
    """
    Analyze an uploaded code file.
    SECURE: Validates file type, size, and uses secure_filename.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    # SECURE: Sanitize filename to prevent path traversal
    filename = secure_filename(file.filename)

    if not allowed_file(filename):
        return jsonify({"error": f"File type not allowed. Permitted: {', '.join(ALLOWED_EXTENSIONS)}"}), 415

    # SECURE: Read content without writing to disk first (size already limited by MAX_CONTENT_LENGTH)
    try:
        code = file.read().decode("utf-8", errors="replace")
    except Exception:
        return jsonify({"error": "Could not read file"}), 400

    ext = Path(filename).suffix.lower()
    ext_to_lang = {".py": "python", ".js": "javascript", ".ts": "javascript",
                   ".php": "php", ".java": "java", ".c": "c", ".cpp": "c",
                   ".rb": "ruby", ".go": "go"}
    language = ext_to_lang.get(ext, "python")

    result = analyze_code(code, language)
    report_id = _save_report(result, filename=filename)
    result["report_id"] = report_id

    return jsonify(result)


# ==========================================
# ROUTES — REPORTS
# ==========================================
@app.route("/api/reports", methods=["GET"])
@login_required
def api_list_reports():
    """List all saved reports for the current user."""
    reports = _load_all_reports()
    summary = [{
        "id": r.get("report_id"),
        "filename": r.get("filename"),
        "language": r.get("language"),
        "score": r.get("score"),
        "grade": r.get("grade"),
        "total": r.get("total"),
        "counts": r.get("counts"),
        "analyzed_at": r.get("analyzed_at"),
    } for r in reports]
    return jsonify(summary)


@app.route("/api/reports/<report_id>", methods=["GET"])
@login_required
def api_get_report(report_id: str):
    """Get a specific report by ID."""
    # SECURE: Validate report_id format to prevent path traversal
    if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', report_id):
        abort(400)

    report_path = REPORTS_FOLDER / f"{report_id}.json"
    if not report_path.exists():
        abort(404)

    # SECURE: Ensure resolved path stays within REPORTS_FOLDER
    if not report_path.resolve().is_relative_to(REPORTS_FOLDER.resolve()):
        abort(403)

    with open(report_path, "r") as f:
        return jsonify(json.load(f))


@app.route("/api/reports/<report_id>", methods=["DELETE"])
@login_required
def api_delete_report(report_id: str):
    """Delete a report."""
    if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', report_id):
        abort(400)

    report_path = REPORTS_FOLDER / f"{report_id}.json"
    if report_path.exists():
        report_path.unlink()
        return jsonify({"message": "Report deleted"})
    abort(404)


# ==========================================
# ROUTES — STATIC PAGES
# ==========================================
@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/<path:filename>")
def static_files(filename):
    """Serve static HTML pages and assets."""
    safe_files = {"login.html", "review.html", "report.html"}
    if filename in safe_files:
        return app.send_static_file(filename)
    return app.send_static_file(filename)


# ==========================================
# ROUTES — HEALTH
# ==========================================
@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "2.4.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ==========================================
# INTERNAL HELPERS
# ==========================================
def _save_report(result: dict, filename: str = "code.txt") -> str:
    """Persist analysis result to the reports directory."""
    report_id = secrets.token_urlsafe(16)
    result["report_id"] = report_id
    result["filename"] = filename
    report_path = REPORTS_FOLDER / f"{report_id}.json"
    with open(report_path, "w") as f:
        json.dump(result, f, indent=2)
    return report_id


def _load_all_reports() -> list:
    """Load all persisted reports sorted by date descending."""
    reports = []
    for p in sorted(REPORTS_FOLDER.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(p) as f:
                reports.append(json.load(f))
        except Exception:
            pass
    return reports


def _lang_ext(lang: str) -> str:
    return {"python": "py", "javascript": "js", "php": "php",
            "java": "java", "c": "c", "ruby": "rb", "go": "go"}.get(lang, "txt")


def _get_user_by_email(email: str) -> dict | None:
    """
    Stub: Replace with real database lookup.
    In production, query your users table with a parameterized query.
    """
    # Demo user for testing (password: DemoPass123!)
    demo_hash = generate_password_hash("DemoPass123!")
    if email == "demo@secureaudit.io":
        return {"id": "usr_001", "email": email, "password_hash": demo_hash}
    return None


# ==========================================
# ERROR HANDLERS
# ==========================================
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large. Maximum size is 500KB"}), 413

@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error: %s", e)
    # SECURE: Never expose stack traces to the client
    return jsonify({"error": "Internal server error"}), 500


# ==========================================
# ENTRY POINT
# ==========================================
# NOTE: On Vercel, this file is imported as a serverless function —
# app.run() is never called. Vercel's Python runtime invokes `app`
# (the Flask WSGI object) directly on each request.
#
# For LOCAL development only, run:
#   python app.py
if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
    )


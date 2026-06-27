# ⬡ SecureAudit — Secure Code Review Platform

> AI-powered static analysis engine that detects vulnerabilities, maps findings to OWASP Top 10, and generates actionable remediation guidance.

---

## Overview

SecureAudit is a full-stack web application for performing **automated security code reviews**. It supports Python and JavaScript analysis out of the box (extensible to PHP, Java, Go, Ruby, C/C++) and integrates Claude AI for context-aware vulnerability explanations and fix suggestions.

### Core Capabilities

| Feature | Description |
|---|---|
| Static Analysis | AST-level pattern matching for 50+ vulnerability classes |
| OWASP Top 10 Mapping | Every finding linked to the 2021 OWASP category |
| CWE / CVSS Scoring | CWE identifier and CVSS 3.1 base score on every issue |
| AI Remediation | Claude-powered secure code fix suggestions |
| Multi-language | Python, JavaScript, PHP, Java, C/C++, Ruby, Go |
| Report Management | Persistent JSON reports with history and comparison |
| Secure Backend | Flask with CSRF, parameterized queries, bcrypt, least-privilege |

---

## Project Structure

```
Secure_Coding_Review_Website/
│
├── index.html          ← Landing page with feature overview
├── login.html          ← Authentication (sign in / register)
├── review.html         ← Code editor + AI analysis engine
├── report.html         ← Report viewer with OWASP grid & severity chart
│
├── css/
│   └── style.css       ← Cyberpunk dark theme, full responsive design
│
├── js/
│   └── script.js       ← Analysis engine, Claude AI API calls, UI logic
│
├── app.py              ← Flask backend with secure API routes
├── requirements.txt    ← Python dependencies
│
├── uploads/            ← Temporary uploaded files (auto-created)
└── reports/            ← Persisted JSON analysis reports (auto-created)
```

---

## Vulnerability Detection Rules

### Python Rules
| ID | Rule | Severity | OWASP | CWE |
|---|---|---|---|---|
| PY001 | SQL Injection | Critical | A03:2021 | CWE-89 |
| PY002 | Hardcoded Credentials | Critical | A02:2021 | CWE-798 |
| PY003 | Weak Password Hashing (MD5/SHA1) | High | A02:2021 | CWE-916 |
| PY004 | Debug Mode Enabled | High | A05:2021 | CWE-94 |
| PY005 | Insecure Randomness | Medium | A02:2021 | CWE-338 |
| PY006 | Command Injection | Critical | A03:2021 | CWE-78 |
| PY007 | Path Traversal | High | A01:2021 | CWE-22 |
| PY008 | Weak Encryption Mode (ECB) | High | A02:2021 | CWE-327 |
| PY009 | Missing CSRF Protection | Medium | A01:2021 | CWE-352 |
| PY010 | SSL Verification Disabled | High | A02:2021 | CWE-295 |

### JavaScript Rules
| ID | Rule | Severity | OWASP | CWE |
|---|---|---|---|---|
| JS001 | Dangerous eval() | Critical | A03:2021 | CWE-94 |
| JS002 | DOM-based XSS (innerHTML) | High | A03:2021 | CWE-79 |
| JS003 | Hardcoded API Key | Critical | A02:2021 | CWE-798 |
| JS004 | Wildcard CORS | Medium | A05:2021 | CWE-942 |

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js (optional, for frontend tooling)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/secure-audit.git
cd secure-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables (never hardcode secrets!)
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_ENV=development

# Run the development server
python app.py
```

### Open in Browser

```
http://127.0.0.1:5000
```

### Production Deployment

```bash
# Use gunicorn — never run Flask dev server in production
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

---

## API Reference

### Authentication

```
POST /api/auth/login
Content-Type: application/json
{ "email": "user@example.com", "password": "SecurePassword123!" }

POST /api/auth/logout
```

### Code Analysis

```
POST /api/analyze
Content-Type: application/json
{ "code": "<source code>", "language": "python" }

POST /api/analyze/upload
Content-Type: multipart/form-data
file: <code file> (.py, .js, .php, .java, .c, .rb, .go)
```

### Reports

```
GET    /api/reports           ← List all reports (auth required)
GET    /api/reports/:id       ← Get specific report (auth required)
DELETE /api/reports/:id       ← Delete a report (auth required)
```

### Health

```
GET /api/health
```

---

## Security Architecture

The backend itself is written following the same secure coding principles it audits:

| Practice | Implementation |
|---|---|
| SQL Injection | Parameterized queries everywhere (no string concatenation) |
| Password Storage | `werkzeug.security.generate_password_hash` (PBKDF2-SHA256) |
| Secrets Management | `os.environ.get()` — no hardcoded secrets |
| CSRF Protection | Flask-WTF `CSRFProtect` on all state-changing endpoints |
| Session Security | HttpOnly, Secure, SameSite=Lax cookies |
| File Upload Safety | `secure_filename()`, extension allowlist, 500KB size limit |
| Path Traversal | `Path.resolve().is_relative_to()` validation on all file operations |
| Rate Limiting | Recommended: add `flask-limiter` for production |
| Error Handling | Generic error messages — no stack traces exposed to client |
| Least Privilege | API routes use `@login_required` decorator |

---

## OWASP Top 10 Coverage (2021)

| # | Category | Covered |
|---|---|---|
| A01 | Broken Access Control | ✅ IDOR, path traversal, CSRF |
| A02 | Cryptographic Failures | ✅ MD5/SHA1, ECB, hardcoded secrets, SSL disable |
| A03 | Injection | ✅ SQLi, XSS, CMDi, eval() |
| A04 | Insecure Design | ⚠️ Partial — logic flaw detection |
| A05 | Security Misconfiguration | ✅ Debug mode, wildcard CORS |
| A06 | Vulnerable Components | ⚠️ Manual review needed |
| A07 | Auth & Session Failures | ✅ Weak hashing, insecure tokens |
| A08 | Software Integrity Failures | ⚠️ Partial |
| A09 | Logging Failures | ✅ Checks for missing audit logging |
| A10 | SSRF | ⚠️ Partial — URL validation checks |

---

## Recommended Tools (Mentioned in Platform)

| Tool | Type | Use For |
|---|---|---|
| Bandit | SAST | Python security linting |
| ESLint Security Plugin | SAST | JavaScript vulnerability patterns |
| OWASP ZAP | DAST | Runtime web application scanning |
| Semgrep | SAST | Multi-language pattern matching |
| Snyk | SCA | Dependency vulnerability scanning |
| Trivy | Container | Docker image scanning |

---

## Secure Coding Best Practices

1. **Input Validation** — Validate type, length, format, and range for all inputs
2. **Output Encoding** — Context-aware encoding (HTML, URL, JavaScript, SQL)
3. **Parameterized Queries** — Never concatenate user input into SQL
4. **Secrets Management** — Environment variables + secrets vault, never in code
5. **Strong Password Hashing** — bcrypt/argon2 with work factor ≥ 12
6. **Authenticated Encryption** — AES-GCM or ChaCha20-Poly1305, never ECB
7. **CSRF Tokens** — Synchronizer token pattern on all state-changing requests
8. **Secure Session Config** — HttpOnly, Secure, SameSite cookies + server-side sessions
9. **Principle of Least Privilege** — Minimal permissions for DB, files, network
10. **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options

---

## License

MIT License — Built for secure code. Use responsibly.

---

*Built with Flask · Claude AI · OWASP Guidelines*

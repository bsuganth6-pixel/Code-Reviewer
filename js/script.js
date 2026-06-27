/* ==========================================
   SECUREAUDIT — MAIN JAVASCRIPT
   Full client-side logic + AI-powered analysis
   ========================================== */

// ==========================================
// GLOBAL STATE
// ==========================================
const AppState = {
  currentAnalysis: null,
  reports: [],
  selectedReport: null,
};

// ==========================================
// CODE TEMPLATES
// ==========================================
const CODE_TEMPLATES = {
  sqli: {
    lang: 'python',
    code: `import sqlite3
import flask
from flask import request, render_template_string

app = flask.Flask(__name__)

def get_db():
    return sqlite3.connect("users.db")

# VULNERABLE: SQL Injection - user input directly concatenated
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    
    db = get_db()
    cursor = db.cursor()
    
    # DANGEROUS: Direct string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login successful: " + username
    return "Invalid credentials"

# VULNERABLE: Second-order SQLi
@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    db = get_db()
    cursor = db.cursor()
    # DANGEROUS: No parameterization
    cursor.execute("SELECT * FROM profiles WHERE user_id = %s" % user_id)
    return str(cursor.fetchall())

# VULNERABLE: Hardcoded credentials
DB_PASSWORD = "admin123"
SECRET_KEY = "mysecretkey"
API_KEY = "sk-prod-abc123xyz789"

if __name__ == "__main__":
    # DANGEROUS: Debug mode in production
    app.run(debug=True, host="0.0.0.0")
`
  },
  xss: {
    lang: 'javascript',
    code: `// Node.js / Express - XSS Vulnerable Application
const express = require('express');
const app = express();

// VULNERABLE: Reflected XSS - unsanitized user input in response
app.get('/search', (req, res) => {
  const query = req.query.q;
  // DANGEROUS: Direct insertion of user input into HTML
  res.send(\`
    <html>
      <body>
        <h2>Search results for: \${query}</h2>
        <div id="results">Showing results for \${query}</div>
      </body>
    </html>
  \`);
});

// VULNERABLE: DOM-based XSS
app.get('/profile', (req, res) => {
  const username = req.query.name;
  res.send(\`
    <script>
      // DANGEROUS: Writing unescaped data to DOM
      document.write("Welcome " + "\${username}");
      var user = location.hash.substring(1);
      document.getElementById("greeting").innerHTML = user;
    </script>
  \`);
});

// VULNERABLE: Stored XSS via comment system
let comments = [];
app.post('/comment', express.json(), (req, res) => {
  // DANGEROUS: Storing unsanitized input
  comments.push(req.body.comment);
  res.json({ success: true });
});

app.get('/comments', (req, res) => {
  // DANGEROUS: Rendering stored unsanitized comments
  let html = comments.map(c => \`<div>\${c}</div>\`).join('');
  res.send(\`<html><body>\${html}</body></html>\`);
});

// VULNERABLE: eval() usage
app.post('/calculate', express.json(), (req, res) => {
  const expr = req.body.expression;
  // DANGEROUS: eval on user input = RCE + XSS
  const result = eval(expr);
  res.json({ result });
});

// VULNERABLE: No CORS restriction
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});

app.listen(3000);
`
  },
  auth: {
    lang: 'python',
    code: `# Broken Authentication & Session Management
import hashlib
import random
import time
from flask import Flask, session, request, redirect

app = Flask(__name__)

# VULNERABLE: Weak secret key
app.secret_key = "secret"

# VULNERABLE: MD5 for password hashing (broken)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: No rate limiting on login
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hash_password(password)  # MD5 - easily cracked
    
    # VULNERABLE: Timing attack possible
    user = db_get_user(username)
    if user and user["password"] == hashed:
        session["user"] = username
        session["role"] = user["role"]
        # VULNERABLE: No session regeneration after login
        return redirect("/dashboard")
    return "Login failed", 401

# VULNERABLE: Insecure password reset
@app.route("/reset-password")
def reset_password():
    email = request.args.get("email")
    # DANGEROUS: Predictable token (timestamp + random)
    token = str(int(time.time())) + str(random.randint(1000, 9999))
    send_reset_email(email, token)
    return "Reset email sent"

# VULNERABLE: No CSRF protection
@app.route("/change-password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect("/login")
    # DANGEROUS: No CSRF token verification
    new_password = request.form["new_password"]
    # DANGEROUS: No complexity check
    update_password(session["user"], hash_password(new_password))
    return "Password changed"

# VULNERABLE: Insecure direct object reference
@app.route("/user/<user_id>/data")
def get_user_data(user_id):
    # DANGEROUS: No authorization check
    return fetch_user_data(user_id)

# VULNERABLE: JWT with none algorithm
import base64, json
def decode_token(token):
    parts = token.split(".")
    # DANGEROUS: Not verifying signature
    payload = json.loads(base64.b64decode(parts[1] + "=="))
    return payload

# Stub functions
def db_get_user(u): return None
def send_reset_email(e, t): pass
def update_password(u, p): pass
def fetch_user_data(i): return {}
`
  },
  crypto: {
    lang: 'python',
    code: `# Cryptographic Failures
import hashlib
import base64
import random
import os

# VULNERABLE: ECB mode (deterministic, leaks patterns)
from Crypto.Cipher import AES

def encrypt_ecb(data, key):
    # DANGEROUS: ECB mode - identical plaintext = identical ciphertext
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded = data + " " * (16 - len(data) % 16)
    return base64.b64encode(cipher.encrypt(padded.encode())).decode()

# VULNERABLE: Weak key derivation
def derive_key_weak(password):
    # DANGEROUS: MD5 for key derivation, no salt, no iterations
    return hashlib.md5(password.encode()).digest()

# VULNERABLE: Hardcoded IV
HARDCODED_IV = b"1234567890123456"  # Never do this!

def encrypt_cbc_bad(data, key):
    from Crypto.Cipher import AES
    # DANGEROUS: Static IV - breaks semantic security
    cipher = AES.new(key, AES.MODE_CBC, iv=HARDCODED_IV)
    return cipher.encrypt(data)

# VULNERABLE: Weak random for crypto operations
def generate_token():
    # DANGEROUS: random module is NOT cryptographically secure
    return str(random.randint(100000, 999999))

# VULNERABLE: SHA1 for password hashing (broken/deprecated)
def store_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# VULNERABLE: No HMAC integrity check
def sign_data(data):
    # DANGEROUS: Just hashing without a secret key
    return hashlib.sha256(data.encode()).hexdigest()

# VULNERABLE: Insecure SSL config
import ssl
def create_ssl_context_bad():
    ctx = ssl.create_default_context()
    # DANGEROUS: Disabling certificate verification
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# VULNERABLE: Storing secrets in environment is better but...
SECRET = "p@ssw0rd123"  # Hardcoded in source
DB_URL = "postgresql://admin:password123@localhost/prod"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
  }
};

// ==========================================
// VULNERABILITY DATABASE
// ==========================================
const VULN_DB = {
  sqli: {
    title: "SQL Injection",
    severity: "critical",
    owasp: "A03:2021",
    cwe: "CWE-89",
    cvss: "9.8",
    line: "Line 18–19",
    vulnerable_code: `query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"`,
    description: "User-supplied input is directly concatenated into an SQL query without sanitization or parameterization. An attacker can manipulate the query structure to bypass authentication, extract data, modify records, or in some configurations execute OS commands.",
    fix: `# SECURE: Use parameterized queries (prepared statements)
cursor.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed_password)
)`,
    recommendations: [
      "Always use parameterized queries or prepared statements",
      "Implement an ORM like SQLAlchemy for abstraction",
      "Apply principle of least privilege to DB accounts",
      "Use input validation as a secondary defense"
    ]
  },
  hardcoded_secret: {
    title: "Hardcoded Credentials / Secrets",
    severity: "critical",
    owasp: "A02:2021",
    cwe: "CWE-798",
    cvss: "9.1",
    line: "Lines 33–35",
    vulnerable_code: `DB_PASSWORD = "admin123"\nSECRET_KEY = "mysecretkey"\nAPI_KEY = "sk-prod-abc123xyz789"`,
    description: "Credentials and secret keys are hardcoded directly in source code. These are trivially discoverable through source code access, version control history, or decompilation, and cannot be rotated without a code change.",
    fix: `# SECURE: Load secrets from environment variables
import os
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SECRET_KEY = os.environ.get("SECRET_KEY")
API_KEY = os.environ.get("API_KEY")
# Better: use a secrets manager (AWS Secrets Manager, HashiCorp Vault)`,
    recommendations: []
  },
  debug_mode: {
    title: "Debug Mode Enabled in Production",
    severity: "high",
    owasp: "A05:2021",
    cwe: "CWE-94",
    cvss: "7.5",
    line: "Line 40",
    vulnerable_code: `app.run(debug=True, host="0.0.0.0")`,
    description: "Flask's debug mode exposes an interactive debugger that allows arbitrary Python code execution in the browser. Combined with binding to all interfaces (0.0.0.0), this is a critical remote code execution risk in any non-local environment.",
    fix: `# SECURE: Disable debug mode and restrict interface
app.run(
    debug=False,
    host="127.0.0.1",  # or use a proper WSGI server
    port=8000
)
# Better: Use gunicorn / uWSGI in production`,
    recommendations: []
  },
  xss_reflected: {
    title: "Reflected Cross-Site Scripting (XSS)",
    severity: "high",
    owasp: "A03:2021",
    cwe: "CWE-79",
    cvss: "7.4",
    line: "Lines 7–14",
    vulnerable_code: `res.send(\`<h2>Search results for: \${query}</h2>\`)`,
    description: "User-controlled input from the query string is rendered directly into the HTML response without escaping. An attacker can craft a URL with malicious JavaScript that executes in victims' browsers, enabling session hijacking, credential theft, or defacement.",
    fix: `// SECURE: Escape HTML entities before rendering
const escapeHtml = (str) => str
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

// Or use a template engine with auto-escaping (Handlebars, Pug)
res.send(\`<h2>Results for: \${escapeHtml(query)}</h2>\`);`,
    recommendations: []
  },
  eval_injection: {
    title: "Code Injection via eval()",
    severity: "critical",
    owasp: "A03:2021",
    cwe: "CWE-94",
    cvss: "9.8",
    line: "Lines 37–40",
    vulnerable_code: `const result = eval(expr); // expr from req.body.expression`,
    description: "Using eval() on user-supplied input allows arbitrary JavaScript code execution on the server. This is a Remote Code Execution (RCE) vulnerability that can lead to full server compromise, data exfiltration, and lateral movement.",
    fix: `// SECURE: Use a safe math parser library
const { create, all } = require('mathjs');
const math = create(all, { matrix: 'Array' });

try {
  const result = math.evaluate(expr); // Sandboxed evaluation
  res.json({ result });
} catch (e) {
  res.status(400).json({ error: 'Invalid expression' });
}`,
    recommendations: []
  },
  weak_hash: {
    title: "Broken Password Hashing (MD5/SHA1)",
    severity: "high",
    owasp: "A02:2021",
    cwe: "CWE-916",
    cvss: "7.5",
    line: "Lines 11–12",
    vulnerable_code: `def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()`,
    description: "MD5 is a broken cryptographic hash function not suitable for password storage. It has no salt (enabling rainbow table attacks) and can be computed billions of times per second on modern GPU hardware, making brute-force attacks trivial.",
    fix: `# SECURE: Use bcrypt, scrypt, or argon2
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)`,
    recommendations: []
  },
  csrf: {
    title: "Missing CSRF Protection",
    severity: "medium",
    owasp: "A01:2021",
    cwe: "CWE-352",
    cvss: "6.5",
    line: "Lines 28–33",
    vulnerable_code: `@app.route("/change-password", methods=["POST"])\ndef change_password():\n    # No CSRF token verification`,
    description: "State-changing endpoints lack Cross-Site Request Forgery (CSRF) token validation. An attacker can trick an authenticated user into submitting malicious requests by embedding forms or XHR calls on a third-party site.",
    fix: `# SECURE: Use Flask-WTF for automatic CSRF protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In forms, include the CSRF token
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

# Or for APIs, use SameSite=Strict cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'`,
    recommendations: []
  },
  ecb_mode: {
    title: "Weak Encryption — ECB Mode",
    severity: "high",
    owasp: "A02:2021",
    cwe: "CWE-327",
    cvss: "7.5",
    line: "Lines 10–14",
    vulnerable_code: `cipher = AES.new(key.encode(), AES.MODE_ECB)`,
    description: "AES-ECB (Electronic Codebook) mode is deterministic — identical plaintext blocks produce identical ciphertext blocks. This leaks data patterns and is fundamentally insecure for any real-world encryption use case.",
    fix: `# SECURE: Use AES-GCM for authenticated encryption
from Crypto.Cipher import AES
import os

def encrypt_gcm(data: bytes, key: bytes) -> dict:
    nonce = os.urandom(16)  # Random nonce each time
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return { 'nonce': nonce, 'ct': ciphertext, 'tag': tag }`,
    recommendations: []
  },
  weak_random: {
    title: "Insecure Randomness for Security Tokens",
    severity: "medium",
    owasp: "A02:2021",
    cwe: "CWE-338",
    cvss: "5.9",
    line: "Lines 29–31",
    vulnerable_code: `return str(random.randint(100000, 999999))`,
    description: "Python's random module uses a Mersenne Twister PRNG which is not cryptographically secure. Tokens generated this way are predictable given enough observations, enabling token forgery attacks.",
    fix: `# SECURE: Use secrets module (Python 3.6+) for all security tokens
import secrets

def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

# For OTP-style tokens
def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)`,
    recommendations: []
  },
};

// ==========================================
// SECURE CODING RECOMMENDATIONS
// ==========================================
const SECURE_RECOMMENDATIONS = [
  {
    title: "Use Parameterized Queries for All Database Operations",
    desc: "Never concatenate user input into SQL strings. Use prepared statements with bound parameters in every database call. This is the single most effective defense against SQL injection."
  },
  {
    title: "Hash Passwords with Bcrypt, Argon2, or scrypt",
    desc: "These algorithms are purpose-built for password hashing — they are slow by design, include automatic salting, and have configurable work factors. Never use MD5, SHA1, or SHA256 for passwords."
  },
  {
    title: "Validate and Encode All Output Rendered in HTML",
    desc: "Apply context-aware output encoding: HTML-encode for HTML context, JavaScript-encode for JS context, URL-encode for URL parameters. Use Content-Security-Policy headers as an additional defense layer."
  },
  {
    title: "Store Secrets in Environment Variables or a Vault",
    desc: "Never commit credentials, API keys, or private keys to source control. Use environment variables for configuration, and a dedicated secrets manager (Vault, AWS Secrets Manager) for production credentials."
  },
  {
    title: "Implement Proper Session Management with CSRF Protection",
    desc: "Regenerate session IDs after login/privilege change. Enforce session timeouts. Use SameSite=Strict or CSRF tokens to prevent cross-site request forgery. Set HttpOnly and Secure flags on all cookies."
  },
  {
    title: "Apply Principle of Least Privilege Everywhere",
    desc: "Database accounts should only have SELECT/INSERT on required tables. File system access should be minimal. API tokens should have scoped permissions. Compartmentalize to limit blast radius of a breach."
  },
  {
    title: "Use Authenticated Encryption (AES-GCM or ChaCha20-Poly1305)",
    desc: "Encryption without authentication allows ciphertext tampering attacks. AES-GCM provides both confidentiality and integrity. Use a unique, randomly generated IV/nonce for every encryption operation."
  },
  {
    title: "Disable Debug Mode and Restrict Attack Surface",
    desc: "Never run applications in debug mode outside localhost. Disable stack traces in production responses. Bind services to required interfaces only. Remove development endpoints before deployment."
  }
];

// ==========================================
// OWASP TOP 10 MAPPING
// ==========================================
const OWASP_TOP10 = [
  { num: "A01", name: "Broken Access Control" },
  { num: "A02", name: "Cryptographic Failures" },
  { num: "A03", name: "Injection" },
  { num: "A04", name: "Insecure Design" },
  { num: "A05", name: "Security Misconfiguration" },
  { num: "A06", name: "Vulnerable Components" },
  { num: "A07", name: "Auth & Session Mgmt" },
  { num: "A08", name: "Software Data Integrity" },
  { num: "A09", name: "Security Logging Failures" },
  { num: "A10", name: "SSRF" },
];

// ==========================================
// SAMPLE REPORTS DATA
// ==========================================
const SAMPLE_REPORTS = [
  {
    id: "rpt_001",
    filename: "app.py",
    lang: "Python",
    date: "May 30, 2025",
    time: "14.2s",
    lines: 147,
    score: 24,
    grade: "F",
    vulns: { critical: 3, high: 2, medium: 2, low: 1, info: 1 },
    owaspFlags: ["A02", "A03", "A05", "A07"],
    findingKeys: ["sqli", "hardcoded_secret", "debug_mode", "weak_hash", "csrf", "weak_random"],
  },
  {
    id: "rpt_002",
    filename: "server.js",
    lang: "JavaScript",
    date: "May 28, 2025",
    time: "11.8s",
    lines: 89,
    score: 38,
    grade: "F",
    vulns: { critical: 2, high: 1, medium: 1, low: 2, info: 0 },
    owaspFlags: ["A03", "A05"],
    findingKeys: ["xss_reflected", "eval_injection", "csrf"],
  },
  {
    id: "rpt_003",
    filename: "crypto_utils.py",
    lang: "Python",
    date: "May 25, 2025",
    time: "9.3s",
    lines: 63,
    score: 31,
    grade: "F",
    vulns: { critical: 1, high: 2, medium: 1, low: 1, info: 2 },
    owaspFlags: ["A02"],
    findingKeys: ["ecb_mode", "weak_random", "hardcoded_secret", "weak_hash"],
  },
  {
    id: "rpt_004",
    filename: "auth_service.go",
    lang: "Go",
    date: "May 20, 2025",
    time: "7.1s",
    lines: 210,
    score: 72,
    grade: "C",
    vulns: { critical: 0, high: 1, medium: 2, low: 3, info: 1 },
    owaspFlags: ["A07"],
    findingKeys: ["csrf", "weak_random"],
  },
  {
    id: "rpt_005",
    filename: "api_gateway.py",
    lang: "Python",
    date: "May 15, 2025",
    time: "18.6s",
    lines: 312,
    score: 85,
    grade: "B",
    vulns: { critical: 0, high: 0, medium: 1, low: 2, info: 3 },
    owaspFlags: ["A05"],
    findingKeys: ["debug_mode"],
  },
];

// ==========================================
// PAGE DETECTION
// ==========================================
const page = document.body.className;

document.addEventListener("DOMContentLoaded", () => {
  if (page.includes("index-page")) initIndex();
  if (page.includes("login-page")) initLogin();
  if (page.includes("review-page")) initReview();
  if (page.includes("report-page")) initReport();
});

// ==========================================
// INDEX PAGE
// ==========================================
function initIndex() {
  // Animate feature cards on scroll
  const cards = document.querySelectorAll(".feature-card");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const delay = parseInt(entry.target.dataset.delay) || 0;
        setTimeout(() => {
          entry.target.style.opacity = "1";
          entry.target.style.transform = "translateY(0)";
        }, delay);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  cards.forEach(card => {
    card.style.opacity = "0";
    card.style.transform = "translateY(30px)";
    card.style.transition = "opacity 0.5s ease, transform 0.5s ease";
    observer.observe(card);
  });

  // Animate stats counter
  animateCounters();
}

function animateCounters() {
  const stats = document.querySelectorAll(".stat-num");
  stats.forEach(stat => {
    const text = stat.textContent;
    const num = parseInt(text.replace(/\D/g, ''));
    if (!num) return;
    const suffix = text.replace(/[\d,]/g, '');
    let start = 0;
    const step = num / 40;
    const timer = setInterval(() => {
      start += step;
      if (start >= num) {
        stat.textContent = num.toLocaleString() + suffix;
        clearInterval(timer);
      } else {
        stat.textContent = Math.floor(start).toLocaleString() + suffix;
      }
    }, 30);
  });
}

// ==========================================
// LOGIN PAGE
// ==========================================
function initLogin() {}

function switchTab(tab) {
  document.getElementById("signinForm").classList.toggle("active", tab === "signin");
  document.getElementById("signupForm").classList.toggle("active", tab === "signup");
  document.getElementById("signinTab").classList.toggle("active", tab === "signin");
  document.getElementById("signupTab").classList.toggle("active", tab === "signup");
}

function togglePw(id, btn) {
  const input = document.getElementById(id);
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
  } else {
    input.type = "password";
    btn.textContent = "👁";
  }
}

function checkStrength(pw) {
  const fill = document.getElementById("strengthFill");
  const label = document.getElementById("strengthLabel");
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const levels = [
    { pct: 0, color: "transparent", text: "Enter a password" },
    { pct: 20, color: "#ff2d55", text: "Very Weak" },
    { pct: 40, color: "#ff6b35", text: "Weak" },
    { pct: 60, color: "#ffcc00", text: "Fair" },
    { pct: 80, color: "#00d4ff", text: "Strong" },
    { pct: 100, color: "#00ff9d", text: "Very Strong ✓" },
  ];

  const lv = levels[score] || levels[0];
  fill.style.width = lv.pct + "%";
  fill.style.background = lv.color;
  label.textContent = lv.text;
  label.style.color = lv.color;
}

function handleLogin() {
  const email = document.getElementById("loginEmail").value;
  const pw = document.getElementById("loginPassword").value;
  const msg = document.getElementById("loginMsg");

  if (!email || !pw) {
    showMsg(msg, "error", "Please enter your email and password.");
    return;
  }

  const btn = document.getElementById("loginBtnText");
  btn.textContent = "Signing in...";

  setTimeout(() => {
    btn.textContent = "Sign In →";
    showMsg(msg, "success", "✓ Login successful! Redirecting to dashboard...");
    setTimeout(() => window.location.href = "review.html", 1200);
  }, 1000);
}

function handleRegister() {
  const msg = document.getElementById("loginMsg");
  showMsg(msg, "success", "✓ Account created! You can now sign in.");
  setTimeout(() => switchTab("signin"), 1500);
}

function demoLogin() {
  document.getElementById("loginEmail").value = "demo@secureaudit.io";
  document.getElementById("loginPassword").value = "DemoPass123!";
  handleLogin();
}

function showMsg(el, type, text) {
  el.className = "login-msg " + type;
  el.textContent = text;
  el.style.display = "block";
}

// ==========================================
// REVIEW PAGE
// ==========================================
function initReview() {
  updateLineNumbers();
}

function updateLineNumbers() {
  const ta = document.getElementById("codeInput");
  if (!ta) return;
  const lines = ta.value.split("\n").length;
  document.getElementById("lineCount").textContent = lines + " lines";
  let nums = "";
  for (let i = 1; i <= lines; i++) nums += i + "\n";
  document.getElementById("lineNumbers").textContent = nums;

  // Sync scroll
  ta.addEventListener("scroll", () => {
    document.getElementById("lineNumbers").scrollTop = ta.scrollTop;
  });
}

function switchEditorTab(tab, btn) {
  document.querySelectorAll(".editor-tab-content").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".etab").forEach(b => b.classList.remove("active"));
  document.getElementById(tab + "Tab").classList.add("active");
  btn.classList.add("active");
}

function clearEditor() {
  document.getElementById("codeInput").value = "";
  updateLineNumbers();
}

function copyCode() {
  const code = document.getElementById("codeInput").value;
  navigator.clipboard.writeText(code).then(() => {
    const btn = event.target;
    btn.textContent = "✓ Copied";
    setTimeout(() => btn.textContent = "📋 Copy", 1500);
  });
}

function loadTemplate(key) {
  const tpl = CODE_TEMPLATES[key];
  if (!tpl) return;
  document.getElementById("codeInput").value = tpl.code;
  document.getElementById("langSelect").value = tpl.lang;
  updateLineNumbers();
  switchEditorTab("paste", document.querySelector(".etab"));
  document.querySelector(".etab").classList.add("active");
}

function dragOver(e) {
  e.preventDefault();
  document.getElementById("uploadZone").classList.add("drag-over");
}

function dragLeave(e) {
  document.getElementById("uploadZone").classList.remove("drag-over");
}

function dropFile(e) {
  e.preventDefault();
  dragLeave(e);
  const file = e.dataTransfer.files[0];
  if (file) processFile(file);
}

function handleFileUpload(e) {
  const file = e.target.files[0];
  if (file) processFile(file);
}

function processFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById("codeInput").value = e.target.result;
    updateLineNumbers();
    // Auto-detect language from extension
    const ext = file.name.split(".").pop().toLowerCase();
    const extMap = { py: "python", js: "javascript", ts: "javascript", php: "php", java: "java", c: "c", cpp: "c", rb: "ruby", go: "go" };
    if (extMap[ext]) document.getElementById("langSelect").value = extMap[ext];
    switchEditorTab("paste", document.querySelectorAll(".etab")[0]);
    document.querySelectorAll(".etab")[0].classList.add("active");
    document.querySelectorAll(".etab")[1].classList.remove("active");
  };
  reader.readAsText(file);
}

// ==========================================
// AI-POWERED ANALYSIS ENGINE
// ==========================================
async function runAnalysis() {
  const code = document.getElementById("codeInput").value.trim();
  if (!code) {
    alert("Please paste some code or upload a file first.");
    return;
  }

  const lang = document.getElementById("langSelect").value;

  // Show progress UI
  document.getElementById("analyzeBtn").disabled = true;
  document.getElementById("analyzeBtnText").textContent = "⟳ Analyzing...";
  document.getElementById("analysisProgress").style.display = "block";
  document.getElementById("resultsSection").style.display = "none";

  const startTime = Date.now();

  // Animate progress steps
  await animateStep("step1", 10, 1000);
  await animateStep("step2", 30, 1200);
  await animateStep("step3", 55, 900);

  // Call Claude AI for real analysis
  let aiFindings = [];
  try {
    aiFindings = await callClaudeAnalysis(code, lang);
  } catch (e) {
    console.error("AI analysis error:", e);
    // Fall back to pattern-based detection
    aiFindings = patternBasedDetection(code, lang);
  }

  await animateStep("step4", 80, 800);
  await animateStep("step5", 100, 600);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  // Render results
  renderResults(aiFindings, elapsed);

  // Save to local storage
  saveReport(lang, code, aiFindings, elapsed);

  // Reset UI
  document.getElementById("analyzeBtn").disabled = false;
  document.getElementById("analyzeBtnText").textContent = "🔍 Analyze Code";
  document.getElementById("analysisProgress").style.display = "none";
  document.getElementById("resultsSection").style.display = "flex";
}

function animateStep(stepId, pct, delay) {
  return new Promise(resolve => {
    const step = document.getElementById(stepId);
    // Mark previous steps done
    const allSteps = ["step1", "step2", "step3", "step4", "step5"];
    const idx = allSteps.indexOf(stepId);
    allSteps.slice(0, idx).forEach(id => {
      const s = document.getElementById(id);
      if (s) { s.classList.remove("active"); s.classList.add("done"); s.querySelector(".step-icon").textContent = "✓"; }
    });
    if (step) { step.classList.add("active"); step.querySelector(".step-icon").textContent = "⟳"; }
    document.getElementById("progressBarFill").style.width = pct + "%";
    setTimeout(resolve, delay);
  });
}

// ==========================================
// CLAUDE AI ANALYSIS
// ==========================================
async function callClaudeAnalysis(code, lang) {
  const systemPrompt = `You are an expert security code auditor specializing in static analysis and vulnerability detection. Analyze the provided ${lang} code for security vulnerabilities.

For each vulnerability found, respond ONLY with a valid JSON array (no markdown, no extra text) with this exact structure:
[
  {
    "title": "Vulnerability name",
    "severity": "critical|high|medium|low|info",
    "owasp": "A0X:2021",
    "cwe": "CWE-XXX",
    "cvss": "X.X",
    "line": "Line X or Lines X-Y",
    "vulnerable_code": "The exact vulnerable code snippet (max 1 line)",
    "description": "Clear explanation of the vulnerability and its impact (2-3 sentences)",
    "fix": "Secure code replacement showing the correct pattern"
  }
]

Focus on: SQL injection, XSS, command injection, hardcoded secrets, weak cryptography, insecure authentication, CSRF, path traversal, insecure deserialization, security misconfigurations, debug mode, insecure randomness, broken access control.

If no vulnerabilities found, return: []
Return ONLY the JSON array, nothing else.`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system: systemPrompt,
      messages: [{ role: "user", content: `Analyze this ${lang} code for security vulnerabilities:\n\n${code}` }]
    })
  });

  const data = await response.json();
  const text = data.content.map(b => b.text || "").join("").trim();
  const clean = text.replace(/```json|```/g, "").trim();
  const parsed = JSON.parse(clean);
  return Array.isArray(parsed) ? parsed : [];
}

// ==========================================
// FALLBACK: PATTERN-BASED DETECTION
// ==========================================
function patternBasedDetection(code, lang) {
  const findings = [];
  const c = code.toLowerCase();

  const patterns = [
    { test: () => /["']\s*\+\s*(username|password|user|email|input|query|id)/.test(code), key: "sqli" },
    { test: () => /\.execute\s*\(\s*[f"'].*%s|%d/.test(code) && !code.includes("?"), key: "sqli" },
    { test: () => /(password|secret|api_key|token)\s*=\s*["'][^"']{4,}["']/.test(code), key: "hardcoded_secret" },
    { test: () => /app\.run\s*\(.*debug\s*=\s*True/.test(code), key: "debug_mode" },
    { test: () => /hashlib\.(md5|sha1)\s*\(/.test(code), key: "weak_hash" },
    { test: () => /document\.write\s*\(|innerHTML\s*=|eval\s*\(/.test(code), key: "xss_reflected" },
    { test: () => /eval\s*\(\s*req|eval\s*\(\s*request/.test(code), key: "eval_injection" },
    { test: () => /random\.randint|Math\.random\(\)/.test(code), key: "weak_random" },
    { test: () => /AES\.MODE_ECB/.test(code), key: "ecb_mode" },
    { test: () => /csrf/i.test(code) === false && /(change.password|delete.user|transfer)/i.test(code), key: "csrf" },
  ];

  patterns.forEach(p => {
    if (p.test() && VULN_DB[p.key] && !findings.find(f => f.title === VULN_DB[p.key].title)) {
      findings.push({ ...VULN_DB[p.key] });
    }
  });

  return findings.length > 0 ? findings : [
    {
      title: "Code Review Complete",
      severity: "info",
      owasp: "N/A",
      cwe: "N/A",
      cvss: "0.0",
      line: "N/A",
      vulnerable_code: "",
      description: "No high-confidence vulnerabilities detected by pattern analysis. Manual review or AI analysis recommended for comprehensive coverage.",
      fix: "Code appears to follow basic security patterns. Continue following OWASP guidelines."
    }
  ];
}

// ==========================================
// RENDER RESULTS
// ==========================================
function renderResults(findings, elapsed) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  document.getElementById("summaryTime").textContent = `⏱ ${elapsed}s`;
  document.getElementById("critCount").querySelector("span").textContent = counts.critical;
  document.getElementById("highCount").querySelector("span").textContent = counts.high;
  document.getElementById("medCount").querySelector("span").textContent = counts.medium;
  document.getElementById("lowCount").querySelector("span").textContent = counts.low;
  document.getElementById("infoCount").querySelector("span").textContent = counts.info;

  const score = computeScore(counts);
  const scoreEl = document.getElementById("scoreNum");
  scoreEl.textContent = score;
  scoreEl.style.color = scoreColor(score);

  // Render finding cards
  const container = document.getElementById("findingsContainer");
  container.innerHTML = findings.map((f, i) => buildFindingCard(f, i)).join("");

  AppState.currentAnalysis = { findings, counts, score, elapsed };
}

function computeScore(counts) {
  let deductions = counts.critical * 25 + counts.high * 15 + counts.medium * 8 + counts.low * 3;
  return Math.max(0, Math.min(100, 100 - deductions));
}

function scoreColor(s) {
  if (s >= 80) return "var(--accent2)";
  if (s >= 60) return "#88ee00";
  if (s >= 40) return "var(--medium)";
  if (s >= 20) return "var(--high)";
  return "var(--critical)";
}

function buildFindingCard(f, idx) {
  const sev = f.severity || "info";
  return `
    <div class="finding-card sev-${sev}" id="finding-${idx}">
      <div class="finding-header" onclick="toggleFinding(${idx})">
        <div class="finding-sev-dot"></div>
        <div class="finding-title">${escHtml(f.title)}</div>
        <div class="finding-tags">
          ${f.owasp !== "N/A" ? `<span class="finding-tag owasp">${escHtml(f.owasp)}</span>` : ""}
          ${f.cwe !== "N/A" ? `<span class="finding-tag cwe">${escHtml(f.cwe)}</span>` : ""}
          <span class="finding-tag cvss" style="color:${sevColor(sev)}">${sev.toUpperCase()} ${f.cvss !== "N/A" ? "· " + f.cvss : ""}</span>
        </div>
        <span class="finding-expand">▼</span>
      </div>
      <div class="finding-body">
        ${f.line ? `<div class="finding-line">📍 ${escHtml(f.line)}</div>` : ""}
        ${f.vulnerable_code ? `<div class="finding-code">${escHtml(f.vulnerable_code)}</div>` : ""}
        <div class="finding-desc">${escHtml(f.description)}</div>
        ${f.fix ? `
          <div class="finding-fix-label">RECOMMENDED FIX</div>
          <div class="finding-fix">${escHtml(f.fix)}</div>
        ` : ""}
      </div>
    </div>`;
}

function sevColor(sev) {
  const map = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)" };
  return map[sev] || "var(--info)";
}

function toggleFinding(idx) {
  document.getElementById("finding-" + idx).classList.toggle("expanded");
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/\n/g, "<br/>");
}

function resetAnalysis() {
  document.getElementById("resultsSection").style.display = "none";
  document.getElementById("codeInput").value = "";
  updateLineNumbers();
}

function exportFindings() {
  if (!AppState.currentAnalysis) return;
  const json = JSON.stringify(AppState.currentAnalysis, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "secureaudit-findings.json"; a.click();
  URL.revokeObjectURL(url);
}

function saveReport(lang, code, findings, elapsed) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  const score = computeScore(counts);

  const report = {
    id: "rpt_" + Date.now(),
    filename: "code_review_" + lang + ".txt",
    lang: lang.charAt(0).toUpperCase() + lang.slice(1),
    date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
    time: elapsed + "s",
    lines: code.split("\n").length,
    score,
    grade: scoreGrade(score),
    vulns: counts,
    owaspFlags: [...new Set(findings.filter(f => f.owasp && f.owasp !== "N/A").map(f => f.owasp.split(":")[0]))],
    findingKeys: findings.map((_, i) => i),
    rawFindings: findings,
    isNew: true,
  };

  let saved = JSON.parse(localStorage.getItem("secureaudit_reports") || "[]");
  saved.unshift(report);
  saved = saved.slice(0, 20);
  localStorage.setItem("secureaudit_reports", JSON.stringify(saved));
}

function scoreGrade(s) {
  if (s >= 90) return "A";
  if (s >= 80) return "B";
  if (s >= 70) return "C";
  if (s >= 60) return "D";
  return "F";
}

// ==========================================
// REPORT PAGE
// ==========================================
function initReport() {
  // Merge stored reports with sample data
  const stored = JSON.parse(localStorage.getItem("secureaudit_reports") || "[]");
  AppState.reports = [...stored, ...SAMPLE_REPORTS];

  // Update stats
  const totalVulns = AppState.reports.reduce((sum, r) =>
    sum + Object.values(r.vulns).reduce((a, b) => a + b, 0), 0);
  const avgScore = Math.round(AppState.reports.reduce((s, r) => s + r.score, 0) / AppState.reports.length);

  document.getElementById("totalScans").textContent = AppState.reports.length;
  document.getElementById("totalVulns").textContent = totalVulns;
  document.getElementById("avgScore").textContent = avgScore;

  renderReportsList(AppState.reports);

  // Auto-open first report
  if (AppState.reports.length > 0) {
    setTimeout(() => openReport(AppState.reports[0].id), 100);
  }
}

function renderReportsList(reports) {
  const list = document.getElementById("reportsList");
  list.innerHTML = reports.map(r => `
    <div class="report-item ${r.isNew ? 'active' : ''}" id="ri_${r.id}" onclick="openReport('${r.id}')">
      <div class="report-item-top">
        <span class="report-item-name">${r.filename}</span>
        <span class="report-item-score score-${r.grade.toLowerCase()}">${r.grade} (${r.score})</span>
      </div>
      <div class="report-item-meta">
        <span class="report-item-date">${r.date} · ${r.lang}</span>
        <span class="report-item-bugs">${Object.values(r.vulns).reduce((a,b)=>a+b,0)} issues</span>
      </div>
    </div>
  `).join("");
}

function filterReports(query) {
  const filtered = AppState.reports.filter(r =>
    r.filename.toLowerCase().includes(query.toLowerCase()) ||
    r.lang.toLowerCase().includes(query.toLowerCase())
  );
  renderReportsList(filtered);
}

function openReport(id) {
  const report = AppState.reports.find(r => r.id === id);
  if (!report) return;

  AppState.selectedReport = report;

  // Update sidebar active state
  document.querySelectorAll(".report-item").forEach(el => el.classList.remove("active"));
  const item = document.getElementById("ri_" + id);
  if (item) item.classList.add("active");

  document.getElementById("reportPlaceholder").style.display = "none";
  document.getElementById("reportContent").style.display = "flex";

  // Header
  document.getElementById("rBadgeLang").textContent = report.lang.toUpperCase();
  document.getElementById("rFilename").textContent = report.filename;
  document.getElementById("rDate").textContent = "📅 " + report.date;
  document.getElementById("rTime").textContent = "⏱ " + report.time;
  document.getElementById("rLines").textContent = "📄 " + report.lines + " lines";

  const scoreEl = document.getElementById("rScoreNum");
  scoreEl.textContent = report.score;
  scoreEl.style.color = scoreColor(report.score);
  document.getElementById("rScoreGrade").textContent = report.grade;
  document.getElementById("rScoreGrade").style.color = scoreColor(report.score);
  document.getElementById("rBigScore").style.color = scoreColor(report.score);

  // Severity chart
  renderSeverityChart(report.vulns);

  // OWASP grid
  renderOwaspGrid(report.owaspFlags);

  // Findings
  renderDetailFindings(report);

  // Recommendations
  renderRecommendations();
}

function renderSeverityChart(vulns) {
  const total = Math.max(1, Object.values(vulns).reduce((a, b) => a + b, 0));
  const rows = [
    { label: "Critical", count: vulns.critical, color: "var(--critical)" },
    { label: "High",     count: vulns.high,     color: "var(--high)" },
    { label: "Medium",   count: vulns.medium,   color: "var(--medium)" },
    { label: "Low",      count: vulns.low,      color: "var(--low)" },
    { label: "Info",     count: vulns.info,     color: "var(--info)" },
  ];

  document.getElementById("severityChart").innerHTML = rows.map(r => `
    <div class="sev-bar-row">
      <span class="sev-bar-label" style="color:${r.color}">${r.label}</span>
      <div class="sev-bar-track">
        <div class="sev-bar-fill" style="width:${(r.count/total)*100}%;background:${r.color}"></div>
      </div>
      <span class="sev-bar-count" style="color:${r.color}">${r.count}</span>
    </div>
  `).join("");
}

function renderOwaspGrid(flagged) {
  document.getElementById("owaspGrid").innerHTML = OWASP_TOP10.map(o => {
    const isFlag = flagged.some(f => f.startsWith(o.num));
    return `
      <div class="owasp-item ${isFlag ? 'flagged' : ''}">
        <div class="owasp-num">${o.num}:2021</div>
        <div class="owasp-name">${o.name}</div>
        <div class="owasp-flag">${isFlag ? '⚠️' : '✅'}</div>
      </div>
    `;
  }).join("");
}

function renderDetailFindings(report) {
  let findings = [];

  // Use raw findings if available (from live analysis)
  if (report.rawFindings) {
    findings = report.rawFindings;
  } else {
    // Use VULN_DB keys for sample reports
    findings = report.findingKeys
      .map(k => VULN_DB[k])
      .filter(Boolean);
  }

  document.getElementById("detailFindings").innerHTML =
    findings.map((f, i) => buildFindingCard(f, "r" + i)).join("");
}

function filterFindings(sev, btn) {
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");

  document.querySelectorAll("#detailFindings .finding-card").forEach(card => {
    if (sev === "all" || card.classList.contains("sev-" + sev)) {
      card.style.display = "";
    } else {
      card.style.display = "none";
    }
  });
}

function renderRecommendations() {
  document.getElementById("recList").innerHTML = SECURE_RECOMMENDATIONS.map((r, i) => `
    <div class="rec-item">
      <div class="rec-num">${String(i+1).padStart(2,"0")}</div>
      <div class="rec-body">
        <div class="rec-title">${r.title}</div>
        <div class="rec-desc">${r.desc}</div>
      </div>
    </div>
  `).join("");
}

function exportReport(format) {
  if (!AppState.selectedReport) return;
  if (format === "json") {
    const json = JSON.stringify(AppState.selectedReport, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `secureaudit-${AppState.selectedReport.filename}.json`; a.click();
  } else {
    alert("PDF export would generate a formatted report in a real deployment. JSON export is available.");
  }
}

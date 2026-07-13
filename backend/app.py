# ============================================================
#  app.py  —  Zero Trust Network Access Simulator
#  Main FastAPI application — all API endpoints
#  Run: uvicorn app:app --reload --port 8000
# ============================================================

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import time

from auth import (
    authenticate_user, create_access_token,
    get_current_active_user, require_admin,
    LoginRequest, TokenResponse, UserPublic, User,
    USERS_DB,
)
from policy_engine import evaluate_access, AccessRequest, VerdictResponse
from database import init_db, log_access, get_logs, get_stats, get_high_risk_users, clear_logs

# ── App setup ─────────────────────────────────────────────────
app = FastAPI(
    title       = "Zero Trust Network Access Simulator",
    description = "NIST SP 800-207 compliant ZTNA implementation",
    version     = "1.0.0",
)

# Allow frontend (any origin during dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://YOUR-USERNAME.github.io",
        "http://localhost:8000",   # keep for local dev
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

@app.on_event("startup")
def startup():
    init_db()
    print("✅  Zero Trust Simulator started — http://localhost:8000")
    print("📖  API docs available at http://localhost:8000/docs")

# ── Root ──────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    index = frontend_path / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {
        "project": "Zero Trust Network Access Simulator",
        "version": "1.0.0",
        "docs":    "/docs",
        "endpoints": ["/login", "/me", "/request-access", "/logs", "/stats", "/simulate-attack", "/users"],
    }

# ── POST /login ───────────────────────────────────────────────
@app.post("/login", response_model=TokenResponse, tags=["Authentication"])
def login(req: LoginRequest):
    """
    Authenticate with username + password.
    Returns a signed JWT token valid for 60 minutes.
    """
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({
        "sub":         user.username,
        "role":        user.role,
        "trust_level": user.trust_level,
    })
    return TokenResponse(
        access_token = token,
        role         = user.role,
        full_name    = user.full_name,
    )

# ── GET /me ───────────────────────────────────────────────────
@app.get("/me", response_model=UserPublic, tags=["Authentication"])
def get_me(current_user: User = Depends(get_current_active_user)):
    """Return the authenticated user's profile. Requires valid JWT."""
    return UserPublic(
        username    = current_user.username,
        full_name   = current_user.full_name,
        email       = current_user.email,
        role        = current_user.role,
        trust_level = current_user.trust_level,
        department  = current_user.department,
    )

# ── POST /request-access ──────────────────────────────────────
@app.post("/request-access", response_model=VerdictResponse, tags=["Zero Trust Engine"])
def request_access(
    req:          AccessRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    🔐 Core Zero Trust endpoint — Policy Enforcement Point (PEP).

    Evaluates the access request using:
    - RBAC permission check (role vs resource)
    - 5-factor continuous risk scoring
    - Adaptive verdict: ALLOW / MFA_REQUIRED / DENY

    Every request is logged regardless of outcome.
    """
    verdict = evaluate_access(
        request     = req,
        user_role   = current_user.role,
        trust_level = current_user.trust_level,
    )

    # Log to SQLite (assume breach — log everything)
    log_access(
        username      = current_user.username,
        full_name     = current_user.full_name,
        role          = current_user.role,
        resource      = req.resource,
        device_health = req.device_health,
        location      = req.location,
        login_hour    = req.login_hour,
        failed_logins = req.failed_logins,
        risk_score    = verdict.risk_score,
        verdict       = verdict.verdict,
        reason        = verdict.reason,
        factors       = verdict.factors,
    )

    return verdict

# ── GET /logs ─────────────────────────────────────────────────
@app.get("/logs", tags=["Monitoring"])
def access_logs(limit: int = 50, current_user: User = Depends(get_current_active_user)):
    """Fetch the last N access log entries. Default: 50."""
    return {"logs": get_logs(limit)}

# ── GET /stats ────────────────────────────────────────────────
@app.get("/stats", tags=["Monitoring"])
def access_stats(current_user: User = Depends(get_current_active_user)):
    """Return aggregated access statistics and high-risk user list."""
    stats = get_stats()
    high_risk = get_high_risk_users()
    total = stats.get("total", 0)
    return {
        "summary": stats,
        "allow_pct":    round(stats["allowed"] / total * 100, 1) if total else 0,
        "mfa_pct":      round(stats["mfa"]     / total * 100, 1) if total else 0,
        "deny_pct":     round(stats["denied"]  / total * 100, 1) if total else 0,
        "high_risk_users": high_risk,
    }

# ── POST /simulate-attack ─────────────────────────────────────
@app.post("/simulate-attack", tags=["Demo"])
def simulate_attack(current_user: User = Depends(get_current_active_user)):
    """
    🚨 Run 5 predefined attack scenarios.
    Shows how Zero Trust blocks attacks that succeed in legacy VPN systems.
    """
    from auth import get_user

    scenarios = [
        {
            "title":       "Stolen credentials — foreign login at 2 AM",
            "description": "Attacker uses Alice's stolen credentials from a foreign country at 2am with 3 failed login attempts before success.",
            "username":    "alice",
            "request":     AccessRequest(resource="prod_db",    device_health="personal",        location="foreign",     login_hour=2,  failed_logins=3),
        },
        {
            "title":       "Intern privilege escalation",
            "description": "Intern Charlie attempts to access the Admin Control Panel — a direct RBAC violation.",
            "username":    "charlie",
            "request":     AccessRequest(resource="admin_panel", device_health="managed",         location="office",      login_hour=10, failed_logins=0),
        },
        {
            "title":       "Unpatched device on public Wi-Fi",
            "description": "Developer Bob accesses the dev environment from an unpatched laptop on a coffee shop Wi-Fi network.",
            "username":    "bob",
            "request":     AccessRequest(resource="dev_env",    device_health="unpatched",       location="public_wifi", login_hour=14, failed_logins=0),
        },
        {
            "title":       "Brute force — multiple failed logins",
            "description": "Unknown entity attempts admin panel access after 5 failed login attempts.",
            "username":    "unknown_user",
            "request":     AccessRequest(resource="admin_panel", device_health="unknown_device",  location="foreign",     login_hour=3,  failed_logins=5),
        },
        {
            "title":       "Normal access — baseline happy path",
            "description": "Admin Alice accesses production DB from the office on a managed device during business hours.",
            "username":    "alice",
            "request":     AccessRequest(resource="prod_db",    device_health="managed",         location="office",      login_hour=10, failed_logins=0),
        },
    ]

    results = []
    for s in scenarios:
        user = get_user(s["username"])
        verdict = evaluate_access(s["request"], user.role, user.trust_level)
        log_access(
            username=user.username, full_name=user.full_name, role=user.role,
            resource=s["request"].resource, device_health=s["request"].device_health,
            location=s["request"].location, login_hour=s["request"].login_hour,
            failed_logins=s["request"].failed_logins, risk_score=verdict.risk_score,
            verdict=verdict.verdict, reason=verdict.reason, factors=verdict.factors,
        )
        results.append({
            "scenario":    s["title"],
            "description": s["description"],
            "user":        user.full_name,
            "role":        user.role,
            "verdict":     verdict.verdict,
            "risk_score":  verdict.risk_score,
            "reason":      verdict.reason,
        })

    return {"attack_simulation": results, "total_scenarios": len(results)}

# ── GET /users ────────────────────────────────────────────────
@app.get("/users", tags=["Admin"])
def list_users(admin: User = Depends(require_admin)):
    """Admin only: list all users, roles, and trust levels."""
    return {
        "users": [
            {
                "username":    u.username,
                "full_name":   u.full_name,
                "role":        u.role,
                "trust_level": u.trust_level,
                "department":  u.department,
                "email":       u.email,
                "disabled":    u.disabled,
            }
            for u in USERS_DB.values()
        ]
    }

# ── DELETE /logs ──────────────────────────────────────────────
@app.delete("/logs", tags=["Admin"])
def delete_logs(admin: User = Depends(require_admin)):
    """Admin only: clear all access logs (useful for demo reset)."""
    clear_logs()
    return {"message": "All access logs cleared."}

# ── GET /health ───────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "service": "Zero Trust ZTNA Simulator", "version": "1.0.0"}

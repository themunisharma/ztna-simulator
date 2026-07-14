# ==============================================================
#  Zero Trust Network Access Simulator
#  Single-file FastAPI backend — optimised for Render deployment
#  Run locally:  uvicorn backend.main:app --reload --port 8000
# ==============================================================

import sqlite3, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────
SECRET_KEY = "ztna-secret-key-change-in-production"
ALGORITHM  = "HS256"
TOKEN_MINUTES = 60

DB_PATH = Path(__file__).parent / "ztna.db"

# ── Password hashing ──────────────────────────────────────────
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_pw(p: str) -> str: return pwd.hash(p)
def check_pw(p: str, h: str) -> bool: return pwd.verify(p, h)

# ── Users ─────────────────────────────────────────────────────
class User(BaseModel):
    username: str
    full_name: str
    role: str
    trust_level: int
    department: str
    hashed_password: str
    disabled: bool = False

USERS: dict[str, User] = {
    "alice": User(username="alice", full_name="Alice Sharma",
        role="admin", trust_level=95, department="IT Security",
        hashed_password=hash_pw("admin@123")),
    "bob": User(username="bob", full_name="Bob Verma",
        role="developer", trust_level=75, department="Engineering",
        hashed_password=hash_pw("dev@123")),
    "charlie": User(username="charlie", full_name="Charlie Patel",
        role="intern", trust_level=40, department="HR",
        hashed_password=hash_pw("intern@123")),
    "unknown_user": User(username="unknown_user", full_name="Unknown Entity",
        role="unknown", trust_level=0, department="None",
        hashed_password=hash_pw("unknown@123")),
}

# ── JWT ───────────────────────────────────────────────────────
def make_token(data: dict) -> str:
    d = data.copy()
    d["exp"] = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    return jwt.encode(d, SECRET_KEY, algorithm=ALGORITHM)

def read_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})

# ── RBAC ──────────────────────────────────────────────────────
RBAC = {
    "admin":     {"public_wiki":True,  "dev_env":True,  "prod_db":True,  "admin_panel":True },
    "developer": {"public_wiki":True,  "dev_env":True,  "prod_db":False, "admin_panel":False},
    "intern":    {"public_wiki":True,  "dev_env":False, "prod_db":False, "admin_panel":False},
    "unknown":   {"public_wiki":False, "dev_env":False, "prod_db":False, "admin_panel":False},
}
SENSITIVITY = {"public_wiki":1,"dev_env":3,"prod_db":5,"admin_panel":5}

# ── Risk scoring ──────────────────────────────────────────────
def score_identity(t: int) -> tuple[int,str]:
    if t>=90: return 0,  "Highly trusted identity"
    if t>=70: return 15, "Trusted identity"
    if t>=30: return 35, "Low-trust identity"
    return 60, "Untrusted / unknown identity"

def score_device(d: str) -> tuple[int,str]:
    return {"managed":(0,"Managed and fully patched"),
            "personal":(20,"Personal device — not IT managed"),
            "unpatched":(40,"Unpatched — known CVEs present"),
            "unknown_device":(60,"Unknown device")}.get(d,(60,"Unrecognised device"))

def score_location(l: str) -> tuple[int,str]:
    return {"office":(0,"Trusted office network"),
            "home_vpn":(10,"Home network via VPN"),
            "public_wifi":(30,"Public Wi-Fi — untrusted"),
            "foreign":(50,"Foreign country — unusual location")}.get(l,(50,"Unknown location"))

def score_time(h: int) -> tuple[int,str]:
    if 9<=h<18: return 0,  "Business hours"
    if 18<=h<23: return 10, "Evening — slightly unusual"
    if h>=23 or h<5: return 25,"Late night — highly unusual"
    return 15, "Early morning"

def score_fails(f: int) -> tuple[int,str]:
    if f==0: return 0,  "No recent failed logins"
    if f<=2: return 16, f"{f} failed attempt(s)"
    if f<=4: return 32, f"{f} failed attempts — possible brute force"
    return 40, f"{f}+ attempts — likely brute force"

# ── Database ──────────────────────────────────────────────────
def init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, username TEXT, full_name TEXT, role TEXT,
        resource TEXT, device TEXT, location TEXT,
        hour INTEGER, fails INTEGER,
        score INTEGER, verdict TEXT, reason TEXT, factors TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY CHECK(id=1),
        total INTEGER DEFAULT 0, allowed INTEGER DEFAULT 0,
        mfa INTEGER DEFAULT 0, denied INTEGER DEFAULT 0
    )""")
    c.execute("INSERT OR IGNORE INTO stats(id) VALUES(1)")
    c.commit(); c.close()

def save_log(u, fn, role, res, dev, loc, hour, fails, score, verdict, reason, factors):
    c = sqlite3.connect(DB_PATH)
    c.execute("INSERT INTO logs VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), u, fn, role, res,
         dev, loc, hour, fails, score, verdict, reason,
         json.dumps(factors)))
    col = {"ALLOW":"allowed","MFA_REQUIRED":"mfa","DENY":"denied"}.get(verdict,"denied")
    c.execute(f"UPDATE stats SET total=total+1,{col}={col}+1 WHERE id=1")
    c.commit(); c.close()

def fetch_logs(n=50):
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    rows = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (n,)).fetchall()
    c.close()
    return [dict(r) for r in rows]

def fetch_stats():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    r = c.execute("SELECT * FROM stats WHERE id=1").fetchone()
    c.close()
    return dict(r) if r else {"total":0,"allowed":0,"mfa":0,"denied":0}

def clear_all():
    c = sqlite3.connect(DB_PATH)
    c.execute("DELETE FROM logs")
    c.execute("UPDATE stats SET total=0,allowed=0,mfa=0,denied=0 WHERE id=1")
    c.commit(); c.close()

# ── Pydantic models ───────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str

class AccessReq(BaseModel):
    resource:      str
    device_health: str
    location:      str
    login_hour:    int
    failed_logins: int

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(title="Zero Trust ZTNA Simulator", version="2.0.0")

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"])

oauth2 = OAuth2PasswordBearer(tokenUrl="/login")

@app.on_event("startup")
def startup(): init_db()

# ── Auth dependency ───────────────────────────────────────────
async def current_user(token: str = Depends(oauth2)) -> User:
    payload = read_token(token)
    u = USERS.get(payload.get("sub"))
    if not u or u.disabled:
        raise HTTPException(401, "User not found")
    return u

async def admin_only(u: User = Depends(current_user)) -> User:
    if u.role != "admin":
        raise HTTPException(403, "Admin access required")
    return u

# ── Endpoints ─────────────────────────────────────────────────
@app.get("/")
def root():
    return {"project":"Zero Trust ZTNA Simulator","version":"2.0.0","docs":"/docs"}

@app.post("/login")
def login(req: LoginReq):
    u = USERS.get(req.username)
    if not u or not check_pw(req.password, u.hashed_password):
        raise HTTPException(401, "Incorrect username or password")
    token = make_token({"sub":u.username,"role":u.role,"trust_level":u.trust_level})
    return {"access_token":token,"token_type":"bearer",
            "role":u.role,"full_name":u.full_name,"trust_level":u.trust_level}

@app.get("/me")
def me(u: User = Depends(current_user)):
    return {"username":u.username,"full_name":u.full_name,
            "role":u.role,"trust_level":u.trust_level,"department":u.department}

@app.post("/request-access")
def request_access(req: AccessReq, u: User = Depends(current_user)):
    # RBAC check first
    role_perms = RBAC.get(u.role, {})
    rbac_ok = role_perms.get(req.resource, False)
    sens = SENSITIVITY.get(req.resource, 1)
    sens_label = ["","Low","Low","Medium","High","Critical"][min(sens,5)]

    if not rbac_ok:
        verdict, score, reason = "DENY", 100, \
            f"RBAC denial — role '{u.role}' cannot access '{req.resource}'"
        factors = []
    else:
        # Compute 5 factors
        i_s, i_r = score_identity(u.trust_level)
        d_s, d_r = score_device(req.device_health)
        l_s, l_r = score_location(req.location)
        t_s, t_r = score_time(req.login_hour)
        f_s, f_r = score_fails(req.failed_logins)
        score = min(i_s+d_s+l_s+t_s+f_s, 100)
        factors = [
            {"name":"Identity Trust","score":i_s,"max":60,"reason":i_r},
            {"name":"Device Health", "score":d_s,"max":60,"reason":d_r},
            {"name":"Location",      "score":l_s,"max":50,"reason":l_r},
            {"name":"Access Time",   "score":t_s,"max":25,"reason":t_r},
            {"name":"Failed Logins", "score":f_s,"max":40,"reason":f_r},
        ]
        if score >= 70:
            verdict = "DENY"
            reason  = f"Risk score {score}/100 exceeds deny threshold (≥70)"
        elif score >= 35 or sens >= 4:
            verdict = "MFA_REQUIRED"
            reason  = f"Step-up MFA required — score {score}/100" if score>=35 \
                      else f"Sensitive resource requires MFA"
        else:
            verdict = "ALLOW"
            reason  = f"Risk score {score}/100 within safe threshold"

    save_log(u.username, u.full_name, u.role, req.resource,
             req.device_health, req.location, req.login_hour,
             req.failed_logins, score, verdict, reason, factors)

    return {"verdict":verdict,"risk_score":score,"rbac_allowed":rbac_ok,
            "reason":reason,"resource":req.resource,
            "sensitivity":sens_label,"factors":factors}

@app.get("/logs")
def logs(limit: int = 50, u: User = Depends(current_user)):
    return {"logs": fetch_logs(limit)}

@app.get("/stats")
def stats(u: User = Depends(current_user)):
    s = fetch_stats()
    total = s.get("total", 0)
    return {
        "summary": s,
        "allow_pct":  round(s["allowed"]/total*100,1) if total else 0,
        "mfa_pct":    round(s["mfa"]    /total*100,1) if total else 0,
        "deny_pct":   round(s["denied"] /total*100,1) if total else 0,
    }

@app.post("/simulate-attack")
def simulate(u: User = Depends(current_user)):
    scenarios = [
        ("alice","stolen-creds foreign 2am","prod_db","personal","foreign",2,3),
        ("charlie","intern privilege escalation","admin_panel","managed","office",10,0),
        ("bob","unpatched device public wifi","dev_env","unpatched","public_wifi",14,0),
        ("unknown_user","brute force attempt","admin_panel","unknown_device","foreign",3,5),
        ("alice","normal access baseline","prod_db","managed","office",10,0),
    ]
    results = []
    for username, title, resource, device, location, hour, fails in scenarios:
        su = USERS[username]
        r = request_access(
            AccessReq(resource=resource, device_health=device,
                      location=location, login_hour=hour, failed_logins=fails), su)
        results.append({"scenario":title,"user":su.full_name,
                        "role":su.role,"verdict":r["verdict"],
                        "risk_score":r["risk_score"],"reason":r["reason"]})
    return {"results": results}

@app.get("/users")
def users(a: User = Depends(admin_only)):
    return {"users":[
        {"username":u.username,"full_name":u.full_name,
         "role":u.role,"trust_level":u.trust_level,"department":u.department}
        for u in USERS.values()
    ]}

@app.delete("/logs")
def delete_logs(a: User = Depends(admin_only)):
    clear_all()
    return {"message":"All logs cleared"}

@app.get("/health")
def health():
    return {"status":"ok","version":"2.0.0"}

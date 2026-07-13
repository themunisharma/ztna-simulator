# Zero Trust Network Access Simulator
**B.Tech Final Year Project — NIST SP 800-207 Compliant ZTNA**

A fully functional Zero Trust Network Access Simulator with a 5-factor continuous
risk scoring engine, RBAC, JWT auth, SOC dashboard, and attack simulation module.

---

## Quick Start (5 commands)

```bash
# 1. Clone / navigate to project folder
cd zero-trust-simulator

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
cd backend
uvicorn app:app --reload --port 8000

# 5. Open the dashboard
# Visit http://localhost:8000 in your browser
```

---

## Test Credentials

| Username      | Password      | Role      | Trust Level |
|---------------|---------------|-----------|-------------|
| alice         | admin@123     | Admin     | 95          |
| bob           | dev@123       | Developer | 75          |
| charlie       | intern@123    | Intern    | 40          |
| unknown_user  | unknown@123   | Unknown   | 0           |

---

## Project Structure

```
zero-trust-simulator/
├── backend/
│   ├── app.py              ← FastAPI app, all endpoints (PEP)
│   ├── auth.py             ← JWT, bcrypt, user management
│   ├── policy_engine.py    ← 5-factor risk scorer + RBAC (PDP)
│   ├── database.py         ← SQLite access log persistence
│   └── ztna.db             ← Auto-created on first run
├── frontend/
│   └── index.html          ← SOC Dashboard (React-free, zero deps)
├── tests/
│   └── test_policy.py      ← 20 unit tests (pytest)
├── requirements.txt
└── README.md
```

---

## API Endpoints

| Method | Endpoint            | Auth     | Description                        |
|--------|---------------------|----------|------------------------------------|
| POST   | /login              | ❌ None  | Get JWT token                      |
| GET    | /me                 | ✅ JWT   | Get current user profile           |
| POST   | /request-access     | ✅ JWT   | **Core ZT engine** — get verdict   |
| GET    | /logs               | ✅ JWT   | Access log history                 |
| GET    | /stats              | ✅ JWT   | Aggregated statistics              |
| POST   | /simulate-attack    | ✅ JWT   | Run 5 attack scenarios             |
| GET    | /users              | ✅ Admin | List all users (admin only)        |
| DELETE | /logs               | ✅ Admin | Clear logs (admin only)            |
| GET    | /docs               | ❌ None  | Interactive API docs (Swagger UI)  |

---

## Risk Scoring Engine

Every request is scored across 5 factors (max 100):

| Factor          | Low (0) | Medium (+20) | High (+40) | Critical (+60) |
|-----------------|---------|--------------|------------|----------------|
| Identity Trust  | Admin   | Developer    | Intern     | Unknown        |
| Device Health   | Managed | Personal     | Unpatched  | Unknown device |
| Login Location  | Office  | Home VPN     | Public WiFi| Foreign        |
| Access Time     | 9–18h   | Evening      | Late night | —              |
| Failed Logins   | 0       | 1–2          | 3–4        | 5+             |

**Verdicts:** Score < 35 → ALLOW · 35–69 → MFA Required · ≥ 70 → DENY

---

## Run Tests

```bash
cd zero-trust-simulator
pip install pytest
pytest tests/ -v
```

Expected: 20 tests passing.

---

## NIST 800-207 Architecture Mapping

| NIST Component              | This Project              |
|-----------------------------|---------------------------|
| Policy Enforcement Point    | app.py — /request-access  |
| Policy Decision Point       | policy_engine.py          |
| Policy Administrator        | RBAC table + thresholds   |
| Trust Algorithm             | compute_risk_score()      |
| Subject (user + device)     | JWT claims + request body |
| Enterprise Resource         | resource parameter        |

---

## Technologies

- **Backend:** Python 3.11, FastAPI, Uvicorn
- **Auth:** JWT (python-jose), bcrypt (passlib)
- **Database:** SQLite3
- **Frontend:** HTML5, Vanilla JS, Chart.js
- **Standard:** NIST SP 800-207

---

*Zero Trust: Never trust. Always verify.*

# ============================================================
#  policy_engine.py  —  Zero Trust Network Access Simulator
#  The Policy Decision Point (PDP) — NIST SP 800-207
#  Computes 5-factor risk score and issues access verdicts
# ============================================================

from pydantic import BaseModel
from typing import Optional

# ── Risk thresholds ───────────────────────────────────────────
ALLOW_THRESHOLD = 35    # score < 35  → ALLOW
DENY_THRESHOLD  = 70    # score >= 70 → DENY
                        # 35–69       → MFA_REQUIRED

# ── RBAC permission matrix ────────────────────────────────────
# Maps (role, resource) → True (allowed) / False (denied)
RBAC: dict[str, dict[str, bool]] = {
    "admin":     {"public_wiki": True,  "dev_env": True,  "prod_db": True,  "admin_panel": True },
    "developer": {"public_wiki": True,  "dev_env": True,  "prod_db": False, "admin_panel": False},
    "intern":    {"public_wiki": True,  "dev_env": False, "prod_db": False, "admin_panel": False},
    "unknown":   {"public_wiki": False, "dev_env": False, "prod_db": False, "admin_panel": False},
}

# Resource sensitivity levels (used for step-up MFA trigger)
RESOURCE_SENSITIVITY: dict[str, int] = {
    "public_wiki":  1,
    "dev_env":      3,
    "prod_db":      5,
    "admin_panel":  5,
}

# ── Pydantic models ───────────────────────────────────────────
class AccessRequest(BaseModel):
    resource:      str            # public_wiki | dev_env | prod_db | admin_panel
    device_health: str            # managed | personal | unpatched | unknown_device
    location:      str            # office | home_vpn | public_wifi | foreign
    login_hour:    int            # 0-23 (hour of the day)
    failed_logins: int            # recent failed login attempts

class RiskFactor(BaseModel):
    name:    str
    score:   int
    max:     int
    reason:  str

class VerdictResponse(BaseModel):
    verdict:          str          # ALLOW | MFA_REQUIRED | DENY
    risk_score:       int          # 0-100
    factors:          list[RiskFactor]
    rbac_allowed:     bool
    reason:           str
    resource:         str
    sensitivity:      str

# ── Factor 1: Identity trust ──────────────────────────────────
def score_identity(trust_level: int) -> RiskFactor:
    """
    Higher trust = lower risk score.
    Admin (95) → 0,  Developer (75) → 15,
    Intern (40) → 35, Unknown (0) → 60
    """
    if trust_level >= 90:
        score, reason = 0,  "Highly trusted identity (admin tier)"
    elif trust_level >= 70:
        score, reason = 15, "Trusted identity (developer tier)"
    elif trust_level >= 30:
        score, reason = 35, "Low-trust identity (intern tier)"
    else:
        score, reason = 60, "Untrusted or unknown identity"
    return RiskFactor(name="Identity Trust", score=score, max=60, reason=reason)

# ── Factor 2: Device health ───────────────────────────────────
def score_device(device_health: str) -> RiskFactor:
    mapping = {
        "managed":        (0,  "Managed and fully patched device"),
        "personal":       (20, "Personal device — not under IT control"),
        "unpatched":      (40, "Unpatched device — known CVEs present"),
        "unknown_device": (60, "Unknown/unrecognised device"),
    }
    score, reason = mapping.get(device_health, (60, "Unrecognised device type"))
    return RiskFactor(name="Device Health", score=score, max=60, reason=reason)

# ── Factor 3: Login location ──────────────────────────────────
def score_location(location: str) -> RiskFactor:
    mapping = {
        "office":       (0,  "Trusted office network"),
        "home_vpn":     (10, "Home network via VPN"),
        "public_wifi":  (30, "Public Wi-Fi — untrusted network"),
        "foreign":      (50, "Foreign country — unusual location"),
    }
    score, reason = mapping.get(location, (50, "Unrecognised or suspicious location"))
    return RiskFactor(name="Login Location", score=score, max=50, reason=reason)

# ── Factor 4: Time of access ──────────────────────────────────
def score_time(login_hour: int) -> RiskFactor:
    """
    Business hours (9–18) → 0
    Evening (18–23)       → 10
    Late night (23–5)     → 25
    Early morning (5–9)   → 15
    """
    if 9 <= login_hour < 18:
        score, reason = 0,  "Business hours — expected access time"
    elif 18 <= login_hour < 23:
        score, reason = 10, "Evening access — slightly unusual"
    elif login_hour >= 23 or login_hour < 5:
        score, reason = 25, "Late night access — highly unusual"
    else:
        score, reason = 15, "Early morning — outside typical hours"
    return RiskFactor(name="Access Time", score=score, max=25, reason=reason)

# ── Factor 5: Failed login attempts ──────────────────────────
def score_failed_logins(failed_logins: int) -> RiskFactor:
    """Penalise recent failed login attempts (brute force signal)."""
    if failed_logins == 0:
        score, reason = 0,  "No recent failed login attempts"
    elif failed_logins <= 2:
        score, reason = 16, f"{failed_logins} recent failed attempt(s) — minor concern"
    elif failed_logins <= 4:
        score, reason = 32, f"{failed_logins} failed attempts — possible brute force"
    else:
        score, reason = 40, f"{failed_logins}+ failed attempts — likely brute force attack"
    return RiskFactor(name="Failed Logins", score=score, max=40, reason=reason)

# ── Core engine function ──────────────────────────────────────
def evaluate_access(
    request: AccessRequest,
    user_role:    str,
    trust_level:  int,
) -> VerdictResponse:
    """
    Main policy decision function.
    Called by the PEP (/request-access endpoint) for every access attempt.

    Steps:
      1. Check RBAC — deny immediately if role lacks permission
      2. Compute 5-factor risk score
      3. Apply verdict thresholds
      4. Return full breakdown to PEP
    """

    # Step 1: RBAC hard gate
    role_permissions = RBAC.get(user_role, {})
    rbac_allowed = role_permissions.get(request.resource, False)

    sensitivity_level = RESOURCE_SENSITIVITY.get(request.resource, 1)
    sensitivity_label = ["", "Low", "Low", "Medium", "High", "Critical"][min(sensitivity_level, 5)]

    if not rbac_allowed:
        return VerdictResponse(
            verdict      = "DENY",
            risk_score   = 100,
            factors      = [],
            rbac_allowed = False,
            reason       = f"RBAC denial — role '{user_role}' has no permission to access '{request.resource}'",
            resource     = request.resource,
            sensitivity  = sensitivity_label,
        )

    # Step 2: Compute individual risk factors
    factors = [
        score_identity(trust_level),
        score_device(request.device_health),
        score_location(request.location),
        score_time(request.login_hour),
        score_failed_logins(request.failed_logins),
    ]

    # Step 3: Aggregate score (capped at 100)
    total_score = min(sum(f.score for f in factors), 100)

    # Step 4: Apply verdict logic
    # High-sensitivity resources (4-5) always trigger MFA even at low scores
    if total_score >= DENY_THRESHOLD:
        verdict = "DENY"
        reason  = f"Risk score {total_score}/100 exceeds deny threshold ({DENY_THRESHOLD})"
    elif total_score >= ALLOW_THRESHOLD or sensitivity_level >= 4:
        verdict = "MFA_REQUIRED"
        reason  = (
            f"Risk score {total_score}/100 requires step-up MFA"
            if total_score >= ALLOW_THRESHOLD
            else f"Sensitive resource '{request.resource}' requires MFA regardless of score"
        )
    else:
        verdict = "ALLOW"
        reason  = f"Risk score {total_score}/100 is within safe threshold — access granted"

    return VerdictResponse(
        verdict      = verdict,
        risk_score   = total_score,
        factors      = factors,
        rbac_allowed = True,
        reason       = reason,
        resource     = request.resource,
        sensitivity  = sensitivity_label,
    )

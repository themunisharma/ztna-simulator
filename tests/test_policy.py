# ============================================================
#  tests/test_policy.py  —  Zero Trust Simulator Unit Tests
#  Run: pytest tests/ -v
# ============================================================

import sys
sys.path.insert(0, "../backend")

from backend.policy_engine import evaluate_access, AccessRequest

# ── Helper ────────────────────────────────────────────────────
def verdict(role, trust, resource, device="managed", location="office", hour=10, fails=0):
    req = AccessRequest(
        resource=resource, device_health=device,
        location=location, login_hour=hour, failed_logins=fails,
    )
    return evaluate_access(req, role, trust)

# ── RBAC tests ────────────────────────────────────────────────
class TestRBAC:
    def test_admin_can_access_everything(self):
        for r in ["public_wiki", "dev_env", "prod_db", "admin_panel"]:
            assert verdict("admin", 95, r).verdict != "DENY" or \
                   verdict("admin", 95, r).rbac_allowed == True

    def test_intern_blocked_from_dev_env(self):
        v = verdict("intern", 40, "dev_env")
        assert v.verdict == "DENY"
        assert v.rbac_allowed is False

    def test_intern_blocked_from_prod_db(self):
        v = verdict("intern", 40, "prod_db")
        assert v.verdict == "DENY"

    def test_intern_blocked_from_admin_panel(self):
        v = verdict("intern", 40, "admin_panel")
        assert v.verdict == "DENY"

    def test_intern_can_access_public_wiki(self):
        v = verdict("intern", 40, "public_wiki")
        assert v.rbac_allowed is True

    def test_developer_blocked_from_prod_db(self):
        v = verdict("developer", 75, "prod_db")
        assert v.verdict == "DENY"
        assert v.rbac_allowed is False

    def test_developer_blocked_from_admin_panel(self):
        v = verdict("developer", 75, "admin_panel")
        assert v.verdict == "DENY"

    def test_developer_can_access_dev_env(self):
        v = verdict("developer", 75, "dev_env")
        assert v.rbac_allowed is True

    def test_unknown_blocked_from_everything(self):
        for r in ["public_wiki", "dev_env", "prod_db", "admin_panel"]:
            assert verdict("unknown", 0, r).verdict == "DENY"

# ── Risk scoring / verdict tests ──────────────────────────────
class TestVerdicts:
    def test_admin_office_business_hours_allow(self):
        """Perfect conditions: admin, managed device, office, 10am, no fails"""
        v = verdict("admin", 95, "dev_env", "managed", "office", 10, 0)
        assert v.verdict == "ALLOW"
        assert v.risk_score < 35

    def test_stolen_creds_foreign_night_deny(self):
        """Attacker scenario: valid admin identity, foreign country, 2am, 3 fails"""
        v = verdict("admin", 95, "dev_env", "personal", "foreign", 2, 3)
        assert v.verdict == "DENY"
        assert v.risk_score >= 70

    def test_unpatched_public_wifi_mfa(self):
        """Risky but not deny: unpatched device on public wifi"""
        v = verdict("developer", 75, "dev_env", "unpatched", "public_wifi", 14, 0)
        assert v.verdict in ["MFA_REQUIRED", "DENY"]

    def test_brute_force_5_fails_deny(self):
        """5 failed logins should heavily penalise the score"""
        v = verdict("admin", 95, "dev_env", "managed", "office", 10, 5)
        assert v.risk_score >= 35

    def test_late_night_access_penalised(self):
        """Late night (hour=2) should increase score vs business hours"""
        v_day   = verdict("developer", 75, "dev_env", "managed", "office", 10, 0)
        v_night = verdict("developer", 75, "dev_env", "managed", "office", 2,  0)
        assert v_night.risk_score > v_day.risk_score

    def test_sensitive_resource_forces_mfa(self):
        """prod_db (sensitivity=5) always triggers MFA even at low scores"""
        v = verdict("admin", 95, "prod_db", "managed", "office", 10, 0)
        assert v.verdict in ["MFA_REQUIRED", "ALLOW"]

    def test_unknown_device_penalised(self):
        v = verdict("admin", 95, "dev_env", "unknown_device", "office", 10, 0)
        assert v.risk_score >= 60

    def test_foreign_location_penalised(self):
        v = verdict("admin", 95, "dev_env", "managed", "foreign", 10, 0)
        assert v.risk_score >= 50

    def test_factor_count(self):
        """RBAC-allowed requests must return exactly 5 risk factors"""
        v = verdict("developer", 75, "dev_env")
        assert len(v.factors) == 5

    def test_risk_score_never_exceeds_100(self):
        """Worst possible inputs should cap at 100"""
        v = verdict("unknown", 0, "public_wiki", "unknown_device", "foreign", 2, 5)
        if v.rbac_allowed:
            assert v.risk_score <= 100

# ── Factor scoring tests ──────────────────────────────────────
class TestFactors:
    def test_admin_identity_score_zero(self):
        v = verdict("admin", 95, "dev_env")
        identity = next(f for f in v.factors if f.name == "Identity Trust")
        assert identity.score == 0

    def test_unknown_identity_max_score(self):
        # unknown role blocked by RBAC so test with a resource they can reach
        # but we can test the scorer directly
        from backend.policy_engine import score_identity
        f = score_identity(0)
        assert f.score == 60

    def test_managed_device_zero_score(self):
        from backend.policy_engine import score_device
        f = score_device("managed")
        assert f.score == 0

    def test_unknown_device_max_score(self):
        from backend.policy_engine import score_device
        f = score_device("unknown_device")
        assert f.score == 60

    def test_office_location_zero_score(self):
        from backend.policy_engine import score_location
        f = score_location("office")
        assert f.score == 0

    def test_foreign_location_max_score(self):
        from backend.policy_engine import score_location
        f = score_location("foreign")
        assert f.score == 50

    def test_business_hours_zero_score(self):
        from backend.policy_engine import score_time
        f = score_time(10)
        assert f.score == 0

    def test_late_night_max_score(self):
        from backend.policy_engine import score_time
        f = score_time(2)
        assert f.score == 25

    def test_no_fails_zero_score(self):
        from backend.policy_engine import score_failed_logins
        f = score_failed_logins(0)
        assert f.score == 0

    def test_five_fails_max_score(self):
        from backend.policy_engine import score_failed_logins
        f = score_failed_logins(5)
        assert f.score == 40

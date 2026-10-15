from fastapi.testclient import TestClient
from backend.app import app

def test_api_health_and_initial_state():
    with TestClient(app) as client:
        # 1. Test courses endpoint
        res = client.get("/api/courses")
        assert res.status_code == 200
        courses = res.json()
        assert len(courses) >= 2

        # 2. Test blocks endpoint (Genesis Block #0 + Seeded Block #1)
        res = client.get("/api/ledger/blocks")
        assert res.status_code == 200
        blocks = res.json()
        assert len(blocks) >= 2
        assert blocks[0]["header"]["index"] == 0

        # 3. Test initial cryptographic audit report
        res = client.get("/api/ledger/audit")
        assert res.status_code == 200
        audit = res.json()
        assert audit["is_valid"] is True
        assert len(audit["issues"]) == 0

def test_api_developer_db_injection_simulation():
    with TestClient(app) as client:
        # Simulate developer injecting fake invite in DB
        res = client.post("/api/simulation/inject-fake-invite-db", json={
            "course_id": "CS-801",
            "fake_student_name": "Eve Malicious (Rogue Developer)"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        # The cryptographic verification MUST report invalid signature!
        assert data["cryptographic_verification"]["is_valid"] is False

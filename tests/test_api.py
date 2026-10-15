import uuid
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

def test_api_auth_workflow():
    with TestClient(app) as client:
        unique_email = f"user_{uuid.uuid4().hex[:6]}@student.edu"
        # Register new student
        reg_res = client.post("/api/auth/register", json={
            "email": unique_email,
            "password": "testpass123",
            "name": "Test User",
            "role": "student"
        })
        assert reg_res.status_code == 200
        data = reg_res.json()
        assert data["success"] is True
        assert "private_key" in data

        # Login
        login_res = client.post("/api/auth/login", json={
            "email": unique_email,
            "password": "testpass123"
        })
        assert login_res.status_code == 200
        login_data = login_res.json()
        assert login_data["profile"]["name"] == "Test User"

def test_api_raw_sql_execution_and_attack():
    with TestClient(app) as client:
        unique_inv_id = f"inv_sql_{uuid.uuid4().hex[:6]}"
        sql_query = f"""
        INSERT OR REPLACE INTO invitations (invite_id, course_id, student_public_key, valid_from, valid_until, nonce, admin_signature, issued_at) 
        VALUES ('{unique_inv_id}', 'CS-801', '04bad000', '2026-01-01', '2026-12-31', 'fake_nonce', 'bad_sig', '2026-10-15');
        """
        res = client.post("/api/simulation/execute-sql", json={"query": sql_query})
        assert res.status_code == 200
        data = res.json()
        assert data["sql_execution"]["success"] is True

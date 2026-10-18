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
        INSERT OR REPLACE INTO invitations (invite_id, course_id, student_identity_hash, valid_from, valid_until, nonce, admin_signature, issued_at, row_seal) 
        VALUES ('{unique_inv_id}', 'CS-801', 'bad_hash_000', '2026-01-01', '2026-12-31', 'fake_nonce', 'bad_sig', '2026-10-15', 'forged_seal');
        """
        res = client.post("/api/simulation/execute-sql", json={"query": sql_query})
        assert res.status_code == 200
        data = res.json()
        assert data["sql_execution"]["success"] is True
        assert data["sql_execution"]["seal_verification"]["tampering_detected"] is True

def test_api_pen_test_endpoints():
    with TestClient(app) as client:
        # 1. DB Snoop
        snoop_res = client.get("/api/simulation/pen-test/db-snoop")
        assert snoop_res.status_code == 200
        snoop_data = snoop_res.json()
        assert "users_table" in snoop_data
        assert "security_assessment" in snoop_data

        # 2. Key Hunting
        key_res = client.get("/api/simulation/pen-test/key-hunting")
        assert key_res.status_code == 200
        key_data = key_res.json()
        assert "verdict" in key_data

        # 3. Decrypt Without Key
        dec_res = client.post("/api/simulation/pen-test/decrypt-without-key", json={})
        assert dec_res.status_code == 200
        dec_data = dec_res.json()
        assert dec_data["decryption_result"] is None
        assert "REJECTED" in dec_data["authenticated_tag_status"]

def test_api_pdf_report_generation():
    with TestClient(app) as client:
        # Seed an enrollment first
        seed_res = client.post("/api/simulation/auto-seed-enrollment")
        assert seed_res.status_code == 200

        # Get the transaction ID from the ledger
        blocks_res = client.get("/api/ledger/blocks")
        assert blocks_res.status_code == 200
        blocks = blocks_res.json()
        assert len(blocks) > 1
        tx = blocks[1]["transactions"][0]
        tx_id = tx["tx_id"]

        # Request the PDF report
        pdf_res = client.get(f"/api/enrollments/report/{tx_id}/pdf?student_name=Alice%20Wonderland")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert len(pdf_res.content) > 1000  # Valid non-empty PDF bytes


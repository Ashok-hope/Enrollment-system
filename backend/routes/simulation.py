import uuid
import datetime
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pydantic import BaseModel
from backend.database import db
from core.crypto_engine import generate_ecdsa_keypair, sign_data_ecdsa, sha256_hex, encrypt_payload_aes_gcm
from core.blockchain import BlockchainLedger
from core.models import InviteCertificate, EnrollmentTransaction, SqlExecutionRequest

router = APIRouter(prefix="/simulation", tags=["Security & Attack Simulation"])

class TamperTxRequest(BaseModel):
    block_index: int
    tx_index: int = 0
    field: str = "encrypted_details"
    fake_value: str = "TAMPERED_DEVELOPER_PAYLOAD_EVE"

class InjectStudentRequest(BaseModel):
    block_index: int
    fake_student_name: str = "Eve Malicious (Rogue Developer)"

@router.post("/execute-sql")
def execute_sql(payload: SqlExecutionRequest):
    """
    Execute raw SQL query directly on the SQLite database (simulating DBA/developer access),
    then immediately runs a cryptographic audit to verify if tampering is caught!
    """
    sql_result = db.execute_raw_sql(payload.query)
    
    # Run audit after the SQL query to see cryptographic impact
    audit_report = db.ledger.audit_ledger(db.courses)
    
    return {
        "sql_execution": sql_result,
        "cryptographic_audit": audit_report.model_dump(),
        "is_ledger_tampered": not audit_report.is_valid,
        "explanation": "If unauthorized rows were inserted or modified without valid ECDSA signatures, the audit flags invalid signatures and broken hash links."
    }

@router.get("/demo-keys")
def get_demo_keys():
    eve_pub, eve_priv = generate_ecdsa_keypair()
    inst = db.get_user_by_email("dr.turing@university.edu")
    alice = db.get_user_by_email("alice@student.edu")
    bob = db.get_user_by_email("bob@student.edu")

    return {
        "instructor": {
            "name": inst.name if inst else "Dr. Alan Turing",
            "email": inst.email if inst else "dr.turing@university.edu",
            "pub_key": inst.pub_key if inst else "",
            "priv_key": inst.priv_key if inst else ""
        },
        "student_alice": {
            "name": alice.name if alice else "Alice Wonderland",
            "email": alice.email if alice else "alice@student.edu",
            "pub_key": alice.pub_key if alice else "",
            "priv_key": alice.priv_key if alice else ""
        },
        "student_bob": {
            "name": bob.name if bob else "Bob Smith",
            "email": bob.email if bob else "bob@student.edu",
            "pub_key": bob.pub_key if bob else "",
            "priv_key": bob.priv_key if bob else ""
        },
        "attacker_eve": {
            "name": "Eve (Rogue Developer / Attacker)",
            "email": "eve@attacker.io",
            "pub_key": eve_pub,
            "priv_key": eve_priv
        }
    }

@router.post("/tamper-tx-data")
def tamper_tx_data(payload: TamperTxRequest):
    result = db.ledger.simulate_tamper_tx_data(
        payload.block_index,
        payload.tx_index,
        payload.field,
        payload.fake_value
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/inject-student-block")
def inject_unauthorized_student(payload: InjectStudentRequest):
    fake_pub, _ = generate_ecdsa_keypair()
    result = db.ledger.simulate_inject_unauthorized_student(
        payload.block_index,
        payload.fake_student_name,
        fake_pub
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/corrupt-block-header")
def corrupt_block_header(block_index: int):
    result = db.ledger.simulate_corrupt_block_header(block_index)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/auto-seed-enrollment")
def auto_seed_enrollment():
    course = db.get_course("CS-801")
    if not course:
        return {"success": False, "error": "CS-801 not found"}

    alice = db.get_user_by_email("alice@student.edu")
    inst = db.get_user_by_email("dr.turing@university.edu")
    if not alice or not inst:
        return {"success": False, "error": "Demo users not found"}

    now = datetime.datetime.now(datetime.timezone.utc)
    nonce_inv = f"inv_{uuid.uuid4().hex[:8]}"
    invite_bytes = BlockchainLedger.compute_invite_signing_bytes(
        course.course_id, alice.pub_key, course.schedule_start, course.schedule_end, nonce_inv
    )
    admin_sig = sign_data_ecdsa(inst.priv_key, invite_bytes)

    invite = InviteCertificate(
        invite_id=f"inv_{uuid.uuid4().hex}",
        course_id=course.course_id,
        student_public_key=alice.pub_key,
        valid_from=course.schedule_start,
        valid_until=course.schedule_end,
        nonce=nonce_inv,
        admin_signature=admin_sig,
        issued_at=now.isoformat()
    )
    db.add_invite(invite)

    sym_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    enc = encrypt_payload_aes_gcm("Alice Wonderland - ID: 2026-CS-409 - CGPA: 3.92", sym_key)

    tx_nonce = f"tx_{uuid.uuid4().hex[:8]}"
    tx_time = now.isoformat()
    raw_tx = {
        "course_id": course.course_id,
        "student_public_key": alice.pub_key,
        "encrypted_details": enc["ciphertext_hex"],
        "iv_hex": enc["iv_hex"],
        "tag_hex": enc["tag_hex"],
        "invite_certificate": invite.model_dump(),
        "timestamp": tx_time,
        "nonce": tx_nonce
    }
    tx_bytes = BlockchainLedger.compute_tx_signing_bytes(raw_tx)
    tx_id = sha256_hex(tx_bytes)
    student_sig = sign_data_ecdsa(alice.priv_key, tx_bytes)

    tx = EnrollmentTransaction(
        tx_id=tx_id,
        course_id=course.course_id,
        student_public_key=alice.pub_key,
        encrypted_details=enc["ciphertext_hex"],
        iv_hex=enc["iv_hex"],
        tag_hex=enc["tag_hex"],
        invite_certificate=invite,
        timestamp=tx_time,
        nonce=tx_nonce,
        student_signature=student_sig
    )

    db.ledger.add_transaction(tx, course)
    course.enrolled_count += 1
    mined_block = db.ledger.mine_block()
    if mined_block:
        db.sync_block_to_sqlite(mined_block)

    return {
        "success": True,
        "message": "Seeded initial Block #1 with Alice Wonderland",
        "block_index": mined_block.header.index if mined_block else None
    }

@router.post("/reset")
def reset_ledger():
    db.reset_to_clean_state()
    return {"success": True, "message": "Blockchain ledger restored to pristine state."}

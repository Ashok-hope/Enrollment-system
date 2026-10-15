import uuid
import datetime
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pydantic import BaseModel
from backend.database import db
from core.crypto_engine import generate_ecdsa_keypair, sign_data_ecdsa, sha256_hex, encrypt_payload_aes_gcm
from core.blockchain import BlockchainLedger
from core.models import InviteCertificate, EnrollmentTransaction

router = APIRouter(prefix="/simulation", tags=["Security & Attack Simulation"])

class TamperTxRequest(BaseModel):
    block_index: int
    tx_index: int = 0
    field: str = "encrypted_details"
    fake_value: str = "TAMPERED_DEVELOPER_PAYLOAD_EVE"

class InjectStudentRequest(BaseModel):
    block_index: int
    fake_student_name: str = "Eve Malicious (Rogue Developer)"

class InjectInviteDbRequest(BaseModel):
    course_id: str
    fake_student_name: str = "Eve Malicious (Rogue Developer)"

@router.get("/demo-keys")
def get_demo_keys():
    """Retrieve pre-generated demo keypairs for easy evaluation."""
    eve_pub, eve_priv = generate_ecdsa_keypair()
    return {
        "instructor": db.demo_instructor,
        "student_alice": db.demo_student,
        "attacker_eve": {
            "name": "Eve (Rogue Developer / Attacker)",
            "pub_key": eve_pub,
            "priv_key": eve_priv
        }
    }

@router.post("/tamper-tx-data")
def tamper_tx_data(payload: TamperTxRequest):
    """Simulate a developer modifying existing transaction data directly in storage."""
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
    """Simulate a developer inserting an unauthorized enrollee directly into a block."""
    fake_pub, _ = generate_ecdsa_keypair()
    result = db.ledger.simulate_inject_unauthorized_student(
        payload.block_index,
        payload.fake_student_name,
        fake_pub
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/inject-fake-invite-db")
def inject_fake_invite_db(payload: InjectInviteDbRequest):
    """
    Simulate a developer with direct DB access inserting a fake 'validated student'
    into the database table WITHOUT the instructor's private key.
    """
    course = db.get_course(payload.course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    fake_pub, _ = generate_ecdsa_keypair()
    fake_invite = InviteCertificate(
        invite_id=f"forged_inv_{uuid.uuid4().hex[:10]}",
        course_id=course.course_id,
        student_public_key=fake_pub,
        valid_from=course.schedule_start,
        valid_until=course.schedule_end,
        nonce="forged_nonce_by_developer",
        admin_signature="bad0000000000000000000000000000000000000000000000000000000000000bad0000000000000000000000000000000000000000000000000000000000000",
        issued_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    # Directly insert into SQLite table (bypassing normal API verification)
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO invitations
            (invite_id, course_id, student_public_key, valid_from, valid_until, nonce, admin_signature, issued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fake_invite.invite_id, fake_invite.course_id, fake_invite.student_public_key,
            fake_invite.valid_from, fake_invite.valid_until, fake_invite.nonce,
            fake_invite.admin_signature, fake_invite.issued_at
        ))
        conn.commit()

    db.invites[fake_invite.invite_id] = fake_invite

    # Test audit verification on this forged invite
    is_valid, msg = db.ledger.verify_invite_certificate(fake_invite, course.instructor_public_key)

    return {
        "success": True,
        "action": "inject_fake_invite_db",
        "injected_invite": fake_invite.model_dump(),
        "cryptographic_verification": {
            "is_valid": is_valid,
            "audit_message": msg,
            "instructor_public_key": course.instructor_public_key
        },
        "conclusion": "The rogue developer successfully added a row to the DB table, but cryptographic verification REJECTED it because the developer cannot forge the Admin's Ed25519/ECDSA signature!"
    }

@router.post("/corrupt-block-header")
def corrupt_block_header(block_index: int):
    """Simulate corrupting a block hash."""
    result = db.ledger.simulate_corrupt_block_header(block_index)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/auto-seed-enrollment")
def auto_seed_enrollment():
    """Create a genuine, cryptographically valid enrollment for Alice in CS-801 so blocks are ready to inspect/tamper."""
    course = db.get_course("CS-801")
    if not course:
        raise HTTPException(status_code=404, detail="Course CS-801 not found")

    alice = db.demo_student
    inst = db.demo_instructor

    # Issue invite
    now = datetime.datetime.now(datetime.timezone.utc)
    nonce_inv = f"inv_{uuid.uuid4().hex[:8]}"
    invite_bytes = BlockchainLedger.compute_invite_signing_bytes(
        course.course_id, alice["pub_key"], course.schedule_start, course.schedule_end, nonce_inv
    )
    admin_sig = sign_data_ecdsa(inst["priv_key"], invite_bytes)

    invite = InviteCertificate(
        invite_id=f"inv_{uuid.uuid4().hex}",
        course_id=course.course_id,
        student_public_key=alice["pub_key"],
        valid_from=course.schedule_start,
        valid_until=course.schedule_end,
        nonce=nonce_inv,
        admin_signature=admin_sig,
        issued_at=now.isoformat()
    )
    db.add_invite(invite)

    # Student payload
    sym_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    enc = encrypt_payload_aes_gcm("Alice Wonderland - ID: 2026-CS-409 - CGPA: 3.92", sym_key)

    tx_nonce = f"tx_{uuid.uuid4().hex[:8]}"
    tx_time = now.isoformat()
    raw_tx = {
        "course_id": course.course_id,
        "student_public_key": alice["pub_key"],
        "encrypted_details": enc["ciphertext_hex"],
        "iv_hex": enc["iv_hex"],
        "tag_hex": enc["tag_hex"],
        "invite_certificate": invite.model_dump(),
        "timestamp": tx_time,
        "nonce": tx_nonce
    }
    tx_bytes = BlockchainLedger.compute_tx_signing_bytes(raw_tx)
    tx_id = sha256_hex(tx_bytes)
    student_sig = sign_data_ecdsa(alice["priv_key"], tx_bytes)

    tx = EnrollmentTransaction(
        tx_id=tx_id,
        course_id=course.course_id,
        student_public_key=alice["pub_key"],
        encrypted_details=enc["ciphertext_hex"],
        iv_hex=enc["iv_hex"],
        tag_hex=enc["tag_hex"],
        invite_certificate=invite,
        timestamp=tx_time,
        nonce=tx_nonce,
        student_signature=student_sig
    )

    db.ledger.add_transaction(tx, course.instructor_public_key)
    course.enrolled_count += 1
    mined_block = db.ledger.mine_block()
    if mined_block:
        db.sync_block_to_sqlite(mined_block)

    return {
        "success": True,
        "message": "Created valid cryptographic enrollment for Alice Wonderland in Block #1.",
        "block_index": mined_block.header.index if mined_block else None,
        "tx_id": tx_id
    }

@router.post("/reset")
def reset_ledger():
    """Reset to clean state."""
    db.reset_to_clean_state()
    return {"success": True, "message": "Blockchain ledger restored to pristine state."}

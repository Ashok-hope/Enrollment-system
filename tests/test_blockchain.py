import pytest
import datetime
import uuid
from core.crypto_engine import generate_ecdsa_keypair, sign_data_ecdsa, sha256_hex
from core.blockchain import BlockchainLedger
from core.models import Course, InviteCertificate, EnrollmentTransaction

def test_blockchain_lifecycle_and_tamper_detection():
    ledger = BlockchainLedger()
    assert len(ledger.chain) == 1 # Genesis block

    # Create instructor and student keypairs
    inst_pub, inst_priv = generate_ecdsa_keypair()
    stud_pub, stud_priv = generate_ecdsa_keypair()

    # Create course
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = (now - datetime.timedelta(minutes=5)).isoformat()
    end_time = (now + datetime.timedelta(hours=2)).isoformat()
    
    course_id = "CS-801"
    course = Course(
        course_id=course_id,
        course_code="CS-801",
        title="Advanced Cryptography",
        description="Core concepts and zero-trust verification",
        instructor_name="Prof. Turing",
        instructor_email="dr.turing@university.edu",
        instructor_public_key=inst_pub,
        capacity=20,
        is_timed=True,
        schedule_start=start_time,
        schedule_end=end_time,
        is_enrollment_open=True,
        created_at=now.isoformat()
    )
    courses_dict = {course_id: course}

    # 1. Admin signs an invitation
    invite_nonce = "inv_nonce_123"
    invite_bytes = BlockchainLedger.compute_invite_signing_bytes(
        course_id, stud_pub, start_time, end_time, invite_nonce
    )
    admin_signature = sign_data_ecdsa(inst_priv, invite_bytes)

    invite_cert = InviteCertificate(
        invite_id=str(uuid.uuid4()),
        course_id=course_id,
        student_public_key=stud_pub,
        valid_from=start_time,
        valid_until=end_time,
        nonce=invite_nonce,
        admin_signature=admin_signature,
        issued_at=now.isoformat()
    )

    # 2. Student signs enrollment transaction
    tx_time = now.isoformat()
    tx_nonce = "tx_nonce_456"
    raw_tx_dict = {
        "course_id": course_id,
        "student_public_key": stud_pub,
        "encrypted_details": "416c696365", # "Alice" hex
        "iv_hex": "01" * 12,
        "tag_hex": "02" * 16,
        "invite_certificate": invite_cert.model_dump(),
        "timestamp": tx_time,
        "nonce": tx_nonce
    }
    tx_bytes = BlockchainLedger.compute_tx_signing_bytes(raw_tx_dict)
    tx_id = sha256_hex(tx_bytes)
    student_signature = sign_data_ecdsa(stud_priv, tx_bytes)

    tx = EnrollmentTransaction(
        tx_id=tx_id,
        course_id=course_id,
        student_public_key=stud_pub,
        encrypted_details=raw_tx_dict["encrypted_details"],
        iv_hex=raw_tx_dict["iv_hex"],
        tag_hex=raw_tx_dict["tag_hex"],
        invite_certificate=invite_cert,
        timestamp=tx_time,
        nonce=tx_nonce,
        student_signature=student_signature
    )

    # Add transaction to ledger
    added, msg = ledger.add_transaction(tx, course)
    assert added is True, msg
    assert len(ledger.pending_transactions) == 1

    # Mine block
    new_block = ledger.mine_block()
    assert new_block is not None
    assert new_block.header.index == 1
    assert len(ledger.chain) == 2

    # Audit ledger -> Must be clean!
    audit_report = ledger.audit_ledger(courses_dict)
    assert audit_report.is_valid is True
    assert len(audit_report.issues) == 0

    # 3. TEST DEVELOPER TAMPERING:
    ledger.simulate_tamper_tx_data(1, 0, "encrypted_details", "deadbeef")
    tampered_audit = ledger.audit_ledger(courses_dict)
    assert tampered_audit.is_valid is False
    assert len(tampered_audit.issues) >= 1

    # 4. TEST DEVELOPER INJECTING UNAUTHORIZED STUDENT:
    ledger.simulate_inject_unauthorized_student(1, "Eve Malicious", "04" + "ee" * 64)
    injection_audit = ledger.audit_ledger(courses_dict)
    assert injection_audit.is_valid is False

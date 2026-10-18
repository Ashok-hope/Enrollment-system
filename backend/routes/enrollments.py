import datetime
from fastapi import APIRouter, HTTPException, Response
from typing import List, Dict, Any, Optional
from core.models import EnrollmentTransaction, Block
from core.crypto_engine import sha256_str
from core.pdf_generator import generate_enrollment_certificate_pdf
from backend.database import db

router = APIRouter(prefix="/enrollments", tags=["Enrollments"])

@router.post("/submit")
def submit_enrollment(tx: EnrollmentTransaction):
    course = db.get_course(tx.course_id)
    if not course:
        course = db.get_course_by_code(tx.course_id)
    if not course:
        raise HTTPException(status_code=404, detail=f"Course '{tx.course_id}' not found")

    if course.enrolled_count >= course.capacity:
        raise HTTPException(status_code=400, detail=f"Course '{course.course_code}' is full (Capacity: {course.capacity})")

    # Set pseudonymized identity hash
    tx.student_identity_hash = sha256_str(tx.student_public_key)

    is_valid, reason = db.ledger.add_transaction(tx, course)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Cryptographic verification rejected: {reason}")

    course.enrolled_count += 1
    db.add_course(course)

    mined_block = db.ledger.mine_block()
    if mined_block:
        db.sync_block_to_sqlite(mined_block)
        from core.crypto_engine import MerkleTree
        tx_hashes = [t.tx_id for t in mined_block.transactions]
        tx_index = next((i for i, t in enumerate(mined_block.transactions) if t.tx_id == tx.tx_id), 0)
        tree = MerkleTree(tx_hashes)
        proof = tree.get_proof(tx_index)

        return {
            "status": "ENROLLED_AND_MINED",
            "message": f"Successfully enrolled in {course.course_code}!",
            "receipt": {
                "block_index": mined_block.header.index,
                "block_hash": mined_block.header.block_hash,
                "merkle_root": mined_block.header.merkle_root,
                "tx_id": tx.tx_id,
                "student_identity_hash": tx.student_identity_hash,
                "merkle_proof": proof,
                "timestamp": mined_block.header.timestamp
            }
        }

    return {
        "status": "QUEUED",
        "message": "Transaction verified and queued into pending pool.",
        "tx_id": tx.tx_id
    }

@router.get("/report/{tx_id}/pdf")
def download_enrollment_report_pdf(tx_id: str, student_name: Optional[str] = None):
    """Generate and return an official, downloadable Cryptographic Enrollment Certificate in PDF format."""
    target_tx = None
    target_block = None
    for block in db.ledger.chain:
        for tx in block.transactions:
            if tx.tx_id.lower() == tx_id.lower():
                target_tx = tx
                target_block = block
                break
        if target_tx:
            break

    if not target_tx or not target_block:
        raise HTTPException(status_code=404, detail="Enrollment transaction not found on blockchain")

    course = db.get_course(target_tx.course_id)
    if not course:
        course = db.get_course_by_code(target_tx.course_id)

    c_code = course.course_code if course else target_tx.course_id
    c_title = course.title if course else "Cryptographic Academic Course"
    inst_name = course.instructor_name if course else "Course Instructor"
    disp_name = student_name or "Verified Enrolled Student"
    student_id_hash = target_tx.student_identity_hash or sha256_str(target_tx.student_public_key)

    pdf_bytes = generate_enrollment_certificate_pdf(
        student_name=disp_name,
        student_identity_hash=student_id_hash,
        course_code=c_code,
        course_title=c_title,
        instructor_name=inst_name,
        block_index=target_block.header.index,
        block_hash=target_block.header.block_hash,
        merkle_root=target_block.header.merkle_root,
        tx_id=target_tx.tx_id,
        student_signature=target_tx.student_signature,
        admin_signature=target_tx.invite_certificate.admin_signature,
        timestamp=target_tx.timestamp
    )

    filename = f"enrollment_certificate_{c_code}_{target_tx.tx_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/pending", response_model=List[EnrollmentTransaction])
def get_pending_transactions():
    return db.ledger.pending_transactions

@router.post("/mine", response_model=Block)
def mine_block():
    block = db.ledger.mine_block()
    if not block:
        raise HTTPException(status_code=400, detail="No pending transactions to mine")
    db.sync_block_to_sqlite(block)
    return block

import datetime
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from core.models import EnrollmentTransaction, Block
from backend.database import db

router = APIRouter(prefix="/enrollments", tags=["Enrollments"])

@router.post("/submit")
def submit_enrollment(tx: EnrollmentTransaction):
    course = db.get_course(tx.course_id)
    if not course:
        raise HTTPException(status_code=404, detail=f"Course '{tx.course_id}' not found")

    # 1. Capacity check
    if course.enrolled_count >= course.capacity:
        raise HTTPException(status_code=400, detail=f"Course '{course.course_code}' is full (Capacity: {course.capacity})")

    # 2. Cryptographic and status verification
    is_valid, reason = db.ledger.add_transaction(tx, course)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Cryptographic verification rejected: {reason}")

    course.enrolled_count += 1
    db.add_course(course)

    # Automatically mine transaction into block
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
                "merkle_proof": proof,
                "timestamp": mined_block.header.timestamp
            }
        }

    return {
        "status": "QUEUED",
        "message": "Transaction verified and queued into pending pool.",
        "tx_id": tx.tx_id
    }

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

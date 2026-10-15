import uuid
import datetime
from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from core.models import InviteCertificate
from core.blockchain import BlockchainLedger
from core.crypto_engine import sign_data_ecdsa
from backend.database import db

router = APIRouter(prefix="/invites", tags=["Invitations"])

class IssueInviteRequest(BaseModel):
    course_id: str
    student_public_key: str
    admin_signature: Optional[str] = None # Provided if client signed directly
    admin_private_key: Optional[str] = None # Provided if using demo/convenience signing

@router.post("/issue", response_model=InviteCertificate)
def issue_invite(payload: IssueInviteRequest):
    course = db.get_course(payload.course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = course.schedule_start
    valid_until = course.schedule_end
    nonce = f"inv_{uuid.uuid4().hex[:12]}"
    invite_id = f"inv_{uuid.uuid4().hex}"

    signing_bytes = BlockchainLedger.compute_invite_signing_bytes(
        course_id=course.course_id,
        student_public_key=payload.student_public_key,
        valid_from=valid_from,
        valid_until=valid_until,
        nonce=nonce
    )

    admin_sig = payload.admin_signature
    if not admin_sig:
        # If client provided private key (or using demo instructor key)
        priv_key = payload.admin_private_key or getattr(db, "demo_instructor", {}).get("priv_key")
        if not priv_key:
            raise HTTPException(
                status_code=400, 
                detail="Missing admin_signature or admin_private_key to sign the certificate"
            )
        admin_sig = sign_data_ecdsa(priv_key, signing_bytes)

    invite = InviteCertificate(
        invite_id=invite_id,
        course_id=course.course_id,
        student_public_key=payload.student_public_key,
        valid_from=valid_from,
        valid_until=valid_until,
        nonce=nonce,
        admin_signature=admin_sig,
        issued_at=now.isoformat()
    )

    # Verify signature before accepting into storage
    is_valid, reason = db.ledger.verify_invite_certificate(invite, course.instructor_public_key)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid invite certificate: {reason}")

    db.add_invite(invite)
    return invite

@router.get("/student/{student_pubkey}", response_model=List[InviteCertificate])
def get_student_invites(student_pubkey: str):
    return db.get_invites_for_student(student_pubkey)

@router.get("/course/{course_id}", response_model=List[InviteCertificate])
def get_course_invites(course_id: str):
    return [inv for inv in db.invites.values() if inv.course_id == course_id]

import uuid
import datetime
from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from core.models import InviteCertificate, InviteRequestCreate, InviteRequestRecord
from core.blockchain import BlockchainLedger
from core.crypto_engine import sign_data_ecdsa
from backend.database import db

router = APIRouter(prefix="/invites", tags=["Invitations"])

class ApproveInviteRequest(BaseModel):
    request_id: str
    instructor_private_key: Optional[str] = None

@router.post("/request", response_model=InviteRequestRecord)
def request_invitation(payload: InviteRequestCreate):
    course = db.get_course(payload.course_id)
    if not course:
        # Check by code
        course = db.get_course_by_code(payload.course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    existing = [r for r in db.requests.values() if r.course_id.upper() == course.course_id.upper() and r.student_email.lower() == payload.student_email.lower()]
    if existing:
        return existing[0]

    record = db.create_invite_request(
        course_id=course.course_id,
        student_name=payload.student_name,
        student_email=payload.student_email,
        student_pubkey=payload.student_public_key
    )
    return record

@router.get("/requests/course/{course_id}", response_model=List[InviteRequestRecord])
def get_course_requests(course_id: str):
    return [r for r in db.requests.values() if r.course_id.upper() == course_id.upper()]

@router.get("/requests/student/{student_email}", response_model=List[InviteRequestRecord])
def get_student_requests(student_email: str):
    return db.get_requests_for_student(student_email)

@router.post("/approve")
def approve_invitation(payload: ApproveInviteRequest):
    req = db.requests.get(payload.request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Invitation request not found")

    course = db.get_course(req.course_id)
    if not course:
        course = db.get_course_by_code(req.course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Associated course not found")

    now = datetime.datetime.now(datetime.timezone.utc)
    nonce = f"inv_{uuid.uuid4().hex[:12]}"
    invite_id = f"inv_{uuid.uuid4().hex}"

    signing_bytes = BlockchainLedger.compute_invite_signing_bytes(
        course_id=course.course_id,
        student_public_key=req.student_public_key,
        valid_from=course.schedule_start,
        valid_until=course.schedule_end,
        nonce=nonce
    )

    priv_key = payload.instructor_private_key
    if not priv_key:
        inst_user = db.get_user_by_email(course.instructor_email)
        if inst_user:
            priv_key = inst_user.priv_key

    if not priv_key:
        raise HTTPException(status_code=400, detail="Instructor private key not available for signing")

    admin_sig = sign_data_ecdsa(priv_key, signing_bytes)

    invite = InviteCertificate(
        invite_id=invite_id,
        course_id=course.course_id,
        student_public_key=req.student_public_key,
        valid_from=course.schedule_start,
        valid_until=course.schedule_end,
        nonce=nonce,
        admin_signature=admin_sig,
        issued_at=now.isoformat()
    )

    is_valid, reason = db.ledger.verify_invite_certificate(invite, course.instructor_public_key)
    if not is_valid:
        raise HTTPException(status_code=500, detail=f"Generated certificate failed verification: {reason}")

    db.add_invite(invite)
    db.update_request_status(req.request_id, "APPROVED", invite_id)

    return {
        "success": True,
        "message": f"Approved invitation for {req.student_name}. Certificate signed.",
        "invite": invite
    }

@router.post("/reject")
def reject_invitation(payload: ApproveInviteRequest):
    req = db.requests.get(payload.request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Invitation request not found")
    db.update_request_status(req.request_id, "REJECTED")
    return {"success": True, "message": f"Rejected invitation request for {req.student_name}."}

@router.get("/certificate/{invite_id}", response_model=InviteCertificate)
def get_invite_by_id(invite_id: str):
    invite = db.invites.get(invite_id)
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation certificate not found")
    return invite

@router.get("/student/{student_pubkey}", response_model=List[InviteCertificate])
def get_student_invites(student_pubkey: str):
    clean_key = student_pubkey.lower().strip()
    return [inv for inv in db.invites.values() if inv.student_public_key.lower().strip() == clean_key]

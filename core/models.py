from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class KeyPairResponse(BaseModel):
    public_key_hex: str
    private_key_hex: Optional[str] = None
    identity_hash: str # SHA-256 of public key

class CourseCreate(BaseModel):
    course_code: str # e.g. "CS-801"
    title: str # e.g. "Advanced Cryptography & Blockchain"
    description: str
    instructor_name: str
    instructor_public_key: str # Hex-encoded Ed25519 public key
    capacity: int = 30
    schedule_start: str # ISO timestamp e.g. "2026-10-15T21:00:00Z"
    schedule_end: str # ISO timestamp e.g. "2026-10-15T23:00:00Z"

class Course(CourseCreate):
    course_id: str # UUID or deterministic hash
    created_at: str
    enrolled_count: int = 0
    status: str = "SCHEDULED" # SCHEDULED, OPEN, CLOSED

class InviteRequest(BaseModel):
    course_id: str
    student_public_key: str
    student_name: str

class InviteCertificate(BaseModel):
    invite_id: str
    course_id: str
    student_public_key: str
    valid_from: str # Schedule start
    valid_until: str # Schedule end
    nonce: str
    admin_signature: str # Hex Ed25519 signature from instructor_public_key
    issued_at: str

class EnrollmentTransaction(BaseModel):
    tx_id: str # SHA-256 hash of tx payload
    course_id: str
    student_public_key: str
    encrypted_details: str # AES-256-GCM encrypted sensitive data (e.g. real name, student ID, CGPA)
    iv_hex: str # AES-GCM IV (12 bytes hex)
    tag_hex: str # AES-GCM Auth Tag (16 bytes hex)
    invite_certificate: InviteCertificate # Cryptographic proof signed by Admin
    timestamp: str # ISO timestamp when student signed
    nonce: str # Unique anti-replay nonce
    student_signature: str # Hex Ed25519 signature of the student

class BlockHeader(BaseModel):
    index: int
    prev_hash: str
    merkle_root: str
    timestamp: str
    nonce: int = 0
    block_hash: str

class Block(BaseModel):
    header: BlockHeader
    transactions: List[EnrollmentTransaction]

class AuditIssue(BaseModel):
    block_index: int
    tx_id: Optional[str] = None
    issue_type: str # HASH_MISMATCH, SIGNATURE_INVALID, MERKLE_ROOT_INVALID, INVITE_FORGERY, TIME_VIOLATION
    description: str
    expected: Optional[str] = None
    actual: Optional[str] = None

class AuditReport(BaseModel):
    is_valid: bool
    total_blocks: int
    total_transactions: int
    issues: List[AuditIssue]
    verified_at: str

# Simulation models
class TamperBlockPayload(BaseModel):
    block_index: int
    tamper_type: str # "modify_tx_data", "inject_fake_student", "corrupt_hash", "inject_unvalidated_invite"
    tx_index: Optional[int] = 0
    fake_student_name: Optional[str] = "Eve Malicious (Rogue Developer)"
    fake_student_pubkey: Optional[str] = None

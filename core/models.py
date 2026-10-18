from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class UserRegister(BaseModel):
    email: str
    password: str
    name: str
    role: str # "student" or "instructor"

class UserLogin(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    user_id: str
    email: str
    name: str
    role: str
    public_key: str
    identity_hash: str # SHA-256 of public key
    created_at: str

class CourseCreate(BaseModel):
    course_code: str # e.g. "CS-801"
    title: str # e.g. "Advanced Cryptography"
    description: str
    instructor_name: str
    instructor_email: str
    instructor_public_key: str
    capacity: int = 30
    is_timed: bool = False # If True: uses schedule_start & end; If False: instructor manually toggles start/stop
    schedule_start: Optional[str] = None
    schedule_end: Optional[str] = None

class Course(BaseModel):
    course_id: str
    course_code: str
    title: str
    description: str
    instructor_name: str
    instructor_email: str
    instructor_public_key: str
    capacity: int = 30
    is_timed: bool = False
    schedule_start: Optional[str] = None
    schedule_end: Optional[str] = None
    is_enrollment_open: bool = False
    created_at: str
    enrolled_count: int = 0
    status: str = "PENDING_START" # "PENDING_START", "OPEN", "CLOSED"

class InviteRequestCreate(BaseModel):
    course_id: str
    student_name: str
    student_email: str
    student_public_key: str

class InviteRequestRecord(BaseModel):
    request_id: str
    course_id: str
    student_name: str
    student_email: str
    student_public_key: str
    student_identity_hash: Optional[str] = None
    status: str # "PENDING", "APPROVED", "REJECTED"
    created_at: str
    invite_id: Optional[str] = None

class InviteCertificate(BaseModel):
    invite_id: str
    course_id: str
    student_public_key: str
    student_identity_hash: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    nonce: str
    admin_signature: str
    issued_at: str

class EnrollmentTransaction(BaseModel):
    tx_id: str
    course_id: str
    student_public_key: str
    student_identity_hash: Optional[str] = None # SHA-256(student_public_key)
    encrypted_details: str # AES-256-GCM ciphertext
    iv_hex: str
    tag_hex: str
    invite_certificate: InviteCertificate
    timestamp: str
    nonce: str
    student_signature: str

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
    issue_type: str
    description: str
    expected: Optional[str] = None
    actual: Optional[str] = None

class AuditReport(BaseModel):
    is_valid: bool
    total_blocks: int
    total_transactions: int
    issues: List[AuditIssue]
    verified_at: str

class SqlExecutionRequest(BaseModel):
    query: str

class PenetrationTestResult(BaseModel):
    test_id: str
    test_name: str
    category: str # "DATA_CONFIDENTIALITY", "KEY_MANAGEMENT", "CRYPTANALYSIS", "SQL_MUTATION"
    attempt_description: str
    outcome: str # "BLOCKED", "DEFENDED", "FAILED"
    proof_data: Dict[str, Any]
    security_verdict: str

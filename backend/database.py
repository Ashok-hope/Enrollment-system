import sqlite3
import json
import uuid
import datetime
from typing import Dict, List, Optional, Any, Tuple
from core.models import Course, InviteCertificate, EnrollmentTransaction, Block, InviteRequestRecord
from core.blockchain import BlockchainLedger
from core.crypto_engine import generate_ecdsa_keypair
from core.auth import hash_password, verify_password, UserRecord, UserProfile
from core.logger import log_event

DB_FILE = "crypto_ledger.db"

class DatabaseManager:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.ledger = BlockchainLedger()
        self.users: Dict[str, UserRecord] = {} # Keyed by email
        self.courses: Dict[str, Course] = {} # Keyed by course_id
        self.invites: Dict[str, InviteCertificate] = {} # Keyed by invite_id
        self.requests: Dict[str, InviteRequestRecord] = {} # Keyed by request_id
        self.init_sqlite()
        self.seed_demo_accounts()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_sqlite(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE,
                    name TEXT,
                    role TEXT,
                    pwd_hash TEXT,
                    salt TEXT,
                    pub_key TEXT,
                    priv_key TEXT,
                    created_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS courses (
                    course_id TEXT PRIMARY KEY,
                    course_code TEXT UNIQUE,
                    title TEXT,
                    description TEXT,
                    instructor_name TEXT,
                    instructor_email TEXT,
                    instructor_public_key TEXT,
                    capacity INTEGER,
                    is_timed INTEGER,
                    schedule_start TEXT,
                    schedule_end TEXT,
                    is_enrollment_open INTEGER,
                    created_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS invitation_requests (
                    request_id TEXT PRIMARY KEY,
                    course_id TEXT,
                    student_name TEXT,
                    student_email TEXT,
                    student_public_key TEXT,
                    status TEXT,
                    created_at TEXT,
                    invite_id TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS invitations (
                    invite_id TEXT PRIMARY KEY,
                    course_id TEXT,
                    student_public_key TEXT,
                    valid_from TEXT,
                    valid_until TEXT,
                    nonce TEXT,
                    admin_signature TEXT,
                    issued_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ledger_blocks (
                    block_index INTEGER PRIMARY KEY,
                    prev_hash TEXT,
                    merkle_root TEXT,
                    timestamp TEXT,
                    nonce INTEGER,
                    block_hash TEXT,
                    raw_block_json TEXT
                )
            """)
            conn.commit()

    def seed_demo_accounts(self):
        """Seed pre-configured accounts: Dr. Turing (Instructor), Alice (Student), Bob (Student)."""
        # 1. Instructor
        self.register_user(
            email="dr.turing@university.edu",
            password="admin123",
            name="Dr. Alan Turing",
            role="instructor"
        )

        # 2. Student Alice
        self.register_user(
            email="alice@student.edu",
            password="alice123",
            name="Alice Wonderland",
            role="student"
        )

        # 3. Student Bob
        self.register_user(
            email="bob@student.edu",
            password="bob123",
            name="Bob Smith",
            role="student"
        )

        # Seed initial courses if empty
        inst = self.get_user_by_email("dr.turing@university.edu")
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Course 1: Untimed / Manual Start
        c1 = Course(
            course_id="CS-801",
            course_code="CS-801",
            title="Applied Cryptography & Zero-Trust Systems",
            description="Hands-on asymmetric digital signatures, Merkle ledgers, and zero-trust verification.",
            instructor_name=inst.name,
            instructor_email=inst.email,
            instructor_public_key=inst.pub_key,
            capacity=30,
            is_timed=False,
            is_enrollment_open=True, # Open for immediate testing!
            created_at=now.isoformat(),
            enrolled_count=0,
            status="OPEN"
        )
        self.add_course(c1)

        # Course 2: Timed Course (Future Semester to demonstrate time-lock!)
        future_start = (now + datetime.timedelta(days=2)).isoformat()
        future_end = (now + datetime.timedelta(days=9)).isoformat()
        c2 = Course(
            course_id="CS-902",
            course_code="CS-902",
            title="Quantum Cryptanalysis & Post-Quantum Algorithms",
            description="Scheduled course demonstrating time-locked verification restrictions.",
            instructor_name=inst.name,
            instructor_email=inst.email,
            instructor_public_key=inst.pub_key,
            capacity=20,
            is_timed=True,
            schedule_start=future_start,
            schedule_end=future_end,
            is_enrollment_open=False,
            created_at=now.isoformat(),
            enrolled_count=0,
            status="SCHEDULED"
        )
        self.add_course(c2)

        # Sync Genesis Block
        self.sync_block_to_sqlite(self.ledger.chain[0])

    def register_user(self, email: str, password: str, name: str, role: str) -> Optional[UserRecord]:
        clean_email = email.lower().strip()
        if clean_email in self.users:
            return self.users[clean_email]

        pub_key, priv_key = generate_ecdsa_keypair()
        pwd_hash, salt = hash_password(password)
        user_id = f"usr_{uuid.uuid4().hex[:10]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        record = UserRecord(
            user_id=user_id,
            email=clean_email,
            name=name,
            role=role,
            pwd_hash=pwd_hash,
            salt=salt,
            pub_key=pub_key,
            priv_key=priv_key,
            created_at=now
        )
        self.users[clean_email] = record

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO users (user_id, email, name, role, pwd_hash, salt, pub_key, priv_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, clean_email, name, role, pwd_hash, salt, pub_key, priv_key, now))
            conn.commit()

        log_event("AUTH", f"Registered new user '{clean_email}' as {role.upper()}")
        return record

    def authenticate_user(self, email: str, password: str) -> Optional[UserRecord]:
        clean_email = email.lower().strip()
        user = self.get_user_by_email(clean_email)
        if not user:
            return None
        if verify_password(password, user.salt, user.pwd_hash):
            log_event("AUTH", f"User '{clean_email}' logged in successfully [{user.role.upper()}]")
            return user
        log_event("AUTH", f"Failed login attempt for '{clean_email}'", level="WARN")
        return None

    def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        clean_email = email.lower().strip()
        if clean_email in self.users:
            return self.users[clean_email]
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (clean_email,))
            row = cursor.fetchone()
            if row:
                u = UserRecord(
                    user_id=row["user_id"],
                    email=row["email"],
                    name=row["name"],
                    role=row["role"],
                    pwd_hash=row["pwd_hash"],
                    salt=row["salt"],
                    pub_key=row["pub_key"],
                    priv_key=row["priv_key"],
                    created_at=row["created_at"]
                )
                self.users[clean_email] = u
                return u
        return None

    def add_course(self, course: Course):
        self.courses[course.course_id] = course
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO courses 
                (course_id, course_code, title, description, instructor_name, instructor_email, 
                 instructor_public_key, capacity, is_timed, schedule_start, schedule_end, is_enrollment_open, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                course.course_id, course.course_code, course.title, course.description,
                course.instructor_name, course.instructor_email, course.instructor_public_key,
                course.capacity, 1 if course.is_timed else 0, course.schedule_start,
                course.schedule_end, 1 if course.is_enrollment_open else 0, course.created_at
            ))
            conn.commit()
        log_event("COURSE", f"Course '{course.course_code}' registered [Mode: {'Timed' if course.is_timed else 'Untimed/Manual'}]")

    def get_course(self, course_id: str) -> Optional[Course]:
        return self.courses.get(course_id)

    def get_course_by_code(self, code: str) -> Optional[Course]:
        clean_code = code.upper().strip()
        for c in self.courses.values():
            if c.course_code.upper() == clean_code or c.course_id.upper() == clean_code:
                return c
        return None

    def toggle_course_enrollment(self, course_id: str, is_open: bool) -> Optional[Course]:
        course = self.get_course(course_id)
        if course:
            course.is_enrollment_open = is_open
            course.status = "OPEN" if is_open else "CLOSED"
            self.add_course(course)
            log_event("COURSE", f"Course '{course.course_code}' enrollment is now: {course.status}")
        return course

    # Invitation Requests
    def create_invite_request(self, course_id: str, student_name: str, student_email: str, student_pubkey: str) -> InviteRequestRecord:
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record = InviteRequestRecord(
            request_id=req_id,
            course_id=course_id,
            student_name=student_name,
            student_email=student_email,
            student_public_key=student_pubkey,
            status="PENDING",
            created_at=now
        )
        self.requests[req_id] = record
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO invitation_requests 
                (request_id, course_id, student_name, student_email, student_public_key, status, created_at, invite_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (req_id, course_id, student_name, student_email, student_pubkey, "PENDING", now, None))
            conn.commit()
        log_event("INVITE", f"Student '{student_name}' ({student_email}) requested invitation for course '{course_id}'")
        return record

    def get_requests_for_course(self, course_id: str) -> List[InviteRequestRecord]:
        return [r for r in self.requests.values() if r.course_id == course_id]

    def get_requests_for_student(self, student_email: str) -> List[InviteRequestRecord]:
        return [r for r in self.requests.values() if r.student_email.lower() == student_email.lower()]

    def update_request_status(self, request_id: str, status: str, invite_id: Optional[str] = None):
        if request_id in self.requests:
            self.requests[request_id].status = status
            if invite_id:
                self.requests[request_id].invite_id = invite_id
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE invitation_requests SET status = ?, invite_id = ? WHERE request_id = ?
                """, (status, invite_id, request_id))
                conn.commit()
            log_event("INVITE", f"Invitation request {request_id} updated to {status}")

    def add_invite(self, invite: InviteCertificate):
        self.invites[invite.invite_id] = invite
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO invitations 
                (invite_id, course_id, student_public_key, valid_from, valid_until, nonce, admin_signature, issued_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                invite.invite_id, invite.course_id, invite.student_public_key,
                invite.valid_from, invite.valid_until, invite.nonce,
                invite.admin_signature, invite.issued_at
            ))
            conn.commit()
        log_event("INVITE", f"Stored invitation certificate '{invite.invite_id}' for student [{invite.student_public_key[:12]}...]")

    def sync_block_to_sqlite(self, block: Block):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ledger_blocks 
                (block_index, prev_hash, merkle_root, timestamp, nonce, block_hash, raw_block_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                block.header.index,
                block.header.prev_hash,
                block.header.merkle_root,
                block.header.timestamp,
                block.header.nonce,
                block.header.block_hash,
                block.model_dump_json()
            ))
            conn.commit()

    # Raw SQL Execution for Attack Lab
    def execute_raw_sql(self, query: str) -> Dict[str, Any]:
        """Execute arbitrary SQL query against the database for academic attack demonstration."""
        log_event("SQL", f"Executing raw SQL: {query}", level="WARN")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query)
                conn.commit()
                # Check if it was a SELECT query
                if query.strip().upper().startswith("SELECT"):
                    rows = [dict(row) for row in cursor.fetchall()]
                    return {
                        "success": True,
                        "type": "SELECT",
                        "row_count": len(rows),
                        "rows": rows[:20],
                        "message": f"Query returned {len(rows)} row(s)."
                    }
                else:
                    return {
                        "success": True,
                        "type": "MUTATION",
                        "rows_affected": cursor.rowcount,
                        "message": f"SQL executed successfully. Rows affected: {cursor.rowcount}."
                    }
            except Exception as e:
                log_event("SQL", f"SQL execution error: {str(e)}", level="ERROR")
                return {
                    "success": False,
                    "error": str(e),
                    "message": f"SQLite error: {str(e)}"
                }

    def reset_to_clean_state(self):
        log_event("SECURITY", "Resetting ledger and database to pristine state...")
        self.ledger = BlockchainLedger()
        self.invites.clear()
        self.courses.clear()
        self.requests.clear()
        self.users.clear()
        # Re-initialize
        self.init_sqlite()
        self.seed_demo_accounts()
        log_event("SECURITY", "System restored to clean state.")

db = DatabaseManager()

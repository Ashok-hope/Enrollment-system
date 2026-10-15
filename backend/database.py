import sqlite3
import json
import uuid
import datetime
from typing import Dict, List, Optional, Any, Tuple
from core.models import Course, InviteCertificate, EnrollmentTransaction, Block, BlockHeader, AuditReport
from core.blockchain import BlockchainLedger
from core.crypto_engine import generate_ecdsa_keypair, sign_data_ecdsa, sha256_hex, encrypt_payload_aes_gcm

DB_FILE = "crypto_ledger.db"

class DatabaseManager:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.ledger = BlockchainLedger()
        self.courses: Dict[str, Course] = {}
        self.invites: Dict[str, InviteCertificate] = {}
        self.init_sqlite()
        self.seed_demo_data()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_sqlite(self):
        """Create database tables for courses, invites, and developer-accessible records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS courses (
                    course_id TEXT PRIMARY KEY,
                    course_code TEXT,
                    title TEXT,
                    description TEXT,
                    instructor_name TEXT,
                    instructor_public_key TEXT,
                    capacity INTEGER,
                    schedule_start TEXT,
                    schedule_end TEXT,
                    created_at TEXT
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

    def seed_demo_data(self):
        """Pre-populate sample course, instructor keypair, and student keypair for quick testing."""
        if self.courses:
            return

        # 1. Create Instructor Keypair
        inst_pub, inst_priv = generate_ecdsa_keypair()
        self.demo_instructor = {
            "name": "Dr. Alan Turing",
            "pub_key": inst_pub,
            "priv_key": inst_priv
        }

        # 2. Create Student Keypair (Alice)
        alice_pub, alice_priv = generate_ecdsa_keypair()
        self.demo_student = {
            "name": "Alice Wonderland",
            "pub_key": alice_pub,
            "priv_key": alice_priv
        }

        # 3. Create Course with active schedule
        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = (now - datetime.timedelta(minutes=30)).isoformat()
        end_time = (now + datetime.timedelta(days=7)).isoformat()

        course_id = "CS-801"
        c1 = Course(
            course_id=course_id,
            course_code="CS-801",
            title="Applied Cryptography & Zero-Trust Architecture",
            description="Hands-on asymmetric digital signatures, Merkle-linked blockchains, and tamper-resistant systems.",
            instructor_name="Dr. Alan Turing",
            instructor_public_key=inst_pub,
            capacity=35,
            schedule_start=start_time,
            schedule_end=end_time,
            created_at=now.isoformat(),
            enrolled_count=0,
            status="OPEN"
        )
        self.courses[course_id] = c1

        # Also create a future course to test time-lock / front-running attack!
        future_start = (now + datetime.timedelta(days=2)).isoformat()
        future_end = (now + datetime.timedelta(days=9)).isoformat()
        c2 = Course(
            course_id="CS-902",
            course_code="CS-902",
            title="Quantum Cryptanalysis & Lattice Signatures",
            description="Future semester course testing time-locked scheduling restrictions.",
            instructor_name="Dr. Alan Turing",
            instructor_public_key=inst_pub,
            capacity=25,
            schedule_start=future_start,
            schedule_end=future_end,
            created_at=now.isoformat(),
            enrolled_count=0,
            status="SCHEDULED"
        )
        self.courses["CS-902"] = c2

        # Sync Genesis Block to SQLite
        self.sync_block_to_sqlite(self.ledger.chain[0])

    def get_course(self, course_id: str) -> Optional[Course]:
        return self.courses.get(course_id)

    def add_course(self, course: Course):
        self.courses[course.course_id] = course
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO courses 
                (course_id, course_code, title, description, instructor_name, instructor_public_key, capacity, schedule_start, schedule_end, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                course.course_id, course.course_code, course.title, course.description,
                course.instructor_name, course.instructor_public_key, course.capacity,
                course.schedule_start, course.schedule_end, course.created_at
            ))
            conn.commit()

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

    def get_invites_for_student(self, student_pubkey: str) -> List[InviteCertificate]:
        return [inv for inv in self.invites.values() if inv.student_public_key.lower() == student_pubkey.lower()]

    def reset_to_clean_state(self):
        """Reset the blockchain ledger to pristine state (useful after running tamper simulations)."""
        self.ledger = BlockchainLedger()
        self.invites.clear()
        self.courses.clear()
        self.seed_demo_data()

# Singleton DB instance
db = DatabaseManager()

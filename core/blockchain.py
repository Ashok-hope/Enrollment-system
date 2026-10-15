import datetime
import uuid
from typing import List, Dict, Optional, Tuple, Any

from core.models import (
    Block, BlockHeader, EnrollmentTransaction, InviteCertificate, 
    AuditReport, AuditIssue, Course
)
from core.crypto_engine import (
    sha256_hex, sha256_str, canonical_json, MerkleTree, 
    verify_signature_ecdsa, sign_data_ecdsa
)
from core.logger import log_event

class BlockchainLedger:
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[EnrollmentTransaction] = []
        self.spent_nonces: set = set()
        self.enrolled_students: set = set() # (course_id, student_pubkey)
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_timestamp = "2026-01-01T00:00:00.000Z"
        merkle_root = sha256_str("GENESIS_MERKLE_ROOT_INIT")
        prev_hash = "0" * 64
        block_hash = self.calculate_block_hash(0, prev_hash, merkle_root, genesis_timestamp, 0)
        
        header = BlockHeader(
            index=0,
            prev_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=genesis_timestamp,
            nonce=0,
            block_hash=block_hash
        )
        genesis_block = Block(header=header, transactions=[])
        self.chain.append(genesis_block)
        log_event("BLOCKCHAIN", f"Genesis Block #0 initialized [Hash: {block_hash[:16]}...]")

    @staticmethod
    def calculate_block_hash(index: int, prev_hash: str, merkle_root: str, timestamp: str, nonce: int) -> str:
        payload = f"{index}:{prev_hash}:{merkle_root}:{timestamp}:{nonce}".encode('utf-8')
        return sha256_hex(payload)

    @staticmethod
    def compute_invite_signing_bytes(course_id: str, student_public_key: str, valid_from: Optional[str], valid_until: Optional[str], nonce: str) -> bytes:
        data = {
            "course_id": course_id,
            "student_public_key": student_public_key,
            "valid_from": valid_from or "UNTIMED",
            "valid_until": valid_until or "UNTIMED",
            "nonce": nonce
        }
        return canonical_json(data)

    @staticmethod
    def compute_tx_signing_bytes(tx: Dict[str, Any]) -> bytes:
        data = {
            "course_id": tx["course_id"],
            "student_public_key": tx["student_public_key"],
            "encrypted_details": tx["encrypted_details"],
            "iv_hex": tx["iv_hex"],
            "tag_hex": tx["tag_hex"],
            "invite_id": tx["invite_certificate"]["invite_id"],
            "admin_signature": tx["invite_certificate"]["admin_signature"],
            "timestamp": tx["timestamp"],
            "nonce": tx["nonce"]
        }
        return canonical_json(data)

    def verify_invite_certificate(self, invite: InviteCertificate, instructor_public_key: str) -> Tuple[bool, str]:
        signing_bytes = self.compute_invite_signing_bytes(
            invite.course_id,
            invite.student_public_key,
            invite.valid_from,
            invite.valid_until,
            invite.nonce
        )
        is_valid = verify_signature_ecdsa(instructor_public_key, signing_bytes, invite.admin_signature)
        if not is_valid:
            return False, "FORGERY DETECTED: Invalid Admin digital signature on invitation certificate."
        return True, "Valid invitation certificate"

    def verify_transaction(self, tx: EnrollmentTransaction, course: Course) -> Tuple[bool, str]:
        # 1. Anti-Replay: check if nonce already spent
        replay_key = f"{tx.student_public_key}:{tx.nonce}"
        if replay_key in self.spent_nonces:
            return False, "REPLAY ATTACK: Nonce has already been spent."

        # 2. Check duplicate enrollment
        enrollment_key = f"{tx.course_id}:{tx.student_public_key}"
        if enrollment_key in self.enrolled_students:
            return False, "DUPLICATE ENROLLMENT: Student is already enrolled in this course."

        # 3. Verify Admin's signature on invitation certificate
        valid_invite, reason = self.verify_invite_certificate(tx.invite_certificate, course.instructor_public_key)
        if not valid_invite:
            return False, f"INVITE VALIDATION FAILED: {reason}"

        # 4. Schedule & Open Status Enforcement
        if course.is_timed and course.schedule_start and course.schedule_end:
            tx_time = tx.timestamp
            if tx_time < course.schedule_start:
                return False, f"TIME-LOCK VIOLATION: Enrollment has not started yet (Starts at: {course.schedule_start}, Tx Time: {tx_time})."
            if tx_time > course.schedule_end:
                return False, f"TIME-LOCK EXPIRED: Enrollment window closed at {course.schedule_end}."
        else:
            if not course.is_enrollment_open:
                return False, "ENROLLMENT CLOSED: Instructor has not started enrollment yet."

        # 5. Verify Student's Digital Signature
        signing_bytes = self.compute_tx_signing_bytes(tx.model_dump())
        computed_tx_id = sha256_hex(signing_bytes)
        if tx.tx_id.lower() != computed_tx_id.lower():
            return False, f"TRANSACTION ID MISMATCH: Expected {computed_tx_id}, got {tx.tx_id}"

        valid_sig = verify_signature_ecdsa(tx.student_public_key, signing_bytes, tx.student_signature)
        if not valid_sig:
            return False, "STUDENT SIGNATURE INVALID: Cryptographic signature mismatch."

        return True, "Transaction is cryptographically valid"

    def add_transaction(self, tx: EnrollmentTransaction, course: Course) -> Tuple[bool, str]:
        is_valid, msg = self.verify_transaction(tx, course)
        if not is_valid:
            log_event("SECURITY", f"Transaction rejected: {msg}", level="WARN")
            return False, msg

        self.pending_transactions.append(tx)
        self.spent_nonces.add(f"{tx.student_public_key}:{tx.nonce}")
        self.enrolled_students.add(f"{tx.course_id}:{tx.student_public_key}")
        log_event("ENROLLMENT", f"Transaction verified for student [{tx.student_public_key[:12]}...] in course {tx.course_id}")
        return True, "Transaction verified and queued for block inclusion."

    def mine_block(self) -> Optional[Block]:
        if not self.pending_transactions:
            return None

        tx_list = list(self.pending_transactions)
        self.pending_transactions.clear()

        last_block = self.chain[-1]
        new_index = last_block.header.index + 1
        prev_hash = last_block.header.block_hash
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        tx_hashes = [tx.tx_id for tx in tx_list]
        merkle_tree = MerkleTree(tx_hashes)
        merkle_root = merkle_tree.root

        block_hash = self.calculate_block_hash(new_index, prev_hash, merkle_root, timestamp, 0)

        header = BlockHeader(
            index=new_index,
            prev_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            nonce=0,
            block_hash=block_hash
        )
        new_block = Block(header=header, transactions=tx_list)
        self.chain.append(new_block)
        log_event("BLOCKCHAIN", f"Mined Block #{new_index} with {len(tx_list)} tx(s) [Hash: {block_hash[:16]}... Merkle: {merkle_root[:16]}...]")
        return new_block

    def audit_ledger(self, courses_dict: Dict[str, Course]) -> AuditReport:
        issues: List[AuditIssue] = []
        total_transactions = 0
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Check Genesis
        genesis = self.chain[0]
        recalc_gen_hash = self.calculate_block_hash(0, genesis.header.prev_hash, genesis.header.merkle_root, genesis.header.timestamp, genesis.header.nonce)
        if recalc_gen_hash.lower() != genesis.header.block_hash.lower():
            issues.append(AuditIssue(
                block_index=0,
                issue_type="GENESIS_CORRUPTED",
                description="Genesis block hash was modified or corrupted.",
                expected=recalc_gen_hash,
                actual=genesis.header.block_hash
            ))

        seen_nonces = set()

        for i in range(1, len(self.chain)):
            curr_block = self.chain[i]
            prev_block = self.chain[i - 1]

            # 1. Check prev_hash link
            if curr_block.header.prev_hash.lower() != prev_block.header.block_hash.lower():
                issues.append(AuditIssue(
                    block_index=curr_block.header.index,
                    issue_type="HASH_CHAIN_BROKEN",
                    description=f"Block #{curr_block.header.index} prev_hash does not match Block #{prev_block.header.index} block_hash.",
                    expected=prev_block.header.block_hash,
                    actual=curr_block.header.prev_hash
                ))

            # 2. Check Merkle Root
            tx_hashes = [tx.tx_id for tx in curr_block.transactions]
            recalc_merkle_root = MerkleTree(tx_hashes).root
            if recalc_merkle_root.lower() != curr_block.header.merkle_root.lower():
                issues.append(AuditIssue(
                    block_index=curr_block.header.index,
                    issue_type="MERKLE_ROOT_INVALID",
                    description=f"Block #{curr_block.header.index} transactions were tampered with; Merkle root recalculation mismatch.",
                    expected=recalc_merkle_root,
                    actual=curr_block.header.merkle_root
                ))

            # 3. Check Block Hash
            recalc_block_hash = self.calculate_block_hash(
                curr_block.header.index,
                curr_block.header.prev_hash,
                curr_block.header.merkle_root,
                curr_block.header.timestamp,
                curr_block.header.nonce
            )
            if recalc_block_hash.lower() != curr_block.header.block_hash.lower():
                issues.append(AuditIssue(
                    block_index=curr_block.header.index,
                    issue_type="BLOCK_HASH_MISMATCH",
                    description=f"Block #{curr_block.header.index} header hash recalculation failed.",
                    expected=recalc_block_hash,
                    actual=curr_block.header.block_hash
                ))

            # 4. Check each Transaction inside the block
            for tx in curr_block.transactions:
                total_transactions += 1
                signing_bytes = self.compute_tx_signing_bytes(tx.model_dump())
                recalc_tx_id = sha256_hex(signing_bytes)

                if tx.tx_id.lower() != recalc_tx_id.lower():
                    issues.append(AuditIssue(
                        block_index=curr_block.header.index,
                        tx_id=tx.tx_id,
                        issue_type="TRANSACTION_DATA_TAMPERED",
                        description=f"Transaction data was modified after signing in Block #{curr_block.header.index}.",
                        expected=recalc_tx_id,
                        actual=tx.tx_id
                    ))

                sig_valid = verify_signature_ecdsa(tx.student_public_key, signing_bytes, tx.student_signature)
                if not sig_valid:
                    issues.append(AuditIssue(
                        block_index=curr_block.header.index,
                        tx_id=tx.tx_id,
                        issue_type="STUDENT_SIGNATURE_INVALID",
                        description=f"Student digital signature verification failed for tx {tx.tx_id[:12]}... (Unauthorized or forged transaction).",
                        expected="Valid cryptographic signature",
                        actual=tx.student_signature[:16] + "..."
                    ))

                course = courses_dict.get(tx.course_id)
                if course:
                    invite_bytes = self.compute_invite_signing_bytes(
                        tx.invite_certificate.course_id,
                        tx.invite_certificate.student_public_key,
                        tx.invite_certificate.valid_from,
                        tx.invite_certificate.valid_until,
                        tx.invite_certificate.nonce
                    )
                    admin_sig_valid = verify_signature_ecdsa(
                        course.instructor_public_key,
                        invite_bytes,
                        tx.invite_certificate.admin_signature
                    )
                    if not admin_sig_valid:
                        issues.append(AuditIssue(
                            block_index=curr_block.header.index,
                            tx_id=tx.tx_id,
                            issue_type="DEVELOPER_INJECTION_DETECTED",
                            description=f"Admin invitation certificate signature is invalid! Rogue developer injection detected in Block #{curr_block.header.index}.",
                            expected=f"Signed by instructor {course.instructor_public_key[:12]}...",
                            actual="Forged or unverified certificate"
                        ))

                replay_key = f"{tx.student_public_key}:{tx.nonce}"
                if replay_key in seen_nonces:
                    issues.append(AuditIssue(
                        block_index=curr_block.header.index,
                        tx_id=tx.tx_id,
                        issue_type="REPLAY_ATTACK_DETECTED",
                        description=f"Replay attack detected: Nonce '{tx.nonce}' was submitted multiple times.",
                        expected="Unique nonces",
                        actual=tx.nonce
                    ))
                seen_nonces.add(replay_key)

        return AuditReport(
            is_valid=(len(issues) == 0),
            total_blocks=len(self.chain),
            total_transactions=total_transactions,
            issues=issues,
            verified_at=now_str
        )

    # Simulation helpers
    def simulate_tamper_tx_data(self, block_index: int, tx_index: int, field_to_alter: str, fake_value: str) -> Dict[str, Any]:
        if block_index <= 0 or block_index >= len(self.chain):
            return {"success": False, "error": f"Invalid block index {block_index}"}
        block = self.chain[block_index]
        if tx_index < 0 or tx_index >= len(block.transactions):
            return {"success": False, "error": f"Invalid transaction index {tx_index}"}
        target_tx = block.transactions[tx_index]
        old_val = getattr(target_tx, field_to_alter, None)
        setattr(target_tx, field_to_alter, fake_value)
        log_event("SECURITY", f"TAMPER SIMULATION: Modified Block #{block_index} Tx #{tx_index} '{field_to_alter}' to '{fake_value}'", level="WARN")
        return {
            "success": True,
            "action": "tamper_tx_data",
            "block_index": block_index,
            "tx_index": tx_index,
            "field": field_to_alter,
            "old_value": str(old_val),
            "new_value": fake_value,
            "message": f"Directly altered '{field_to_alter}' in Block #{block_index} storage."
        }

    def simulate_inject_unauthorized_student(self, block_index: int, fake_student_name: str, fake_pubkey: str) -> Dict[str, Any]:
        if block_index <= 0 or block_index >= len(self.chain):
            return {"success": False, "error": f"Invalid block index {block_index}"}
        block = self.chain[block_index]
        fake_invite = InviteCertificate(
            invite_id=str(uuid.uuid4()),
            course_id="CS-801",
            student_public_key=fake_pubkey,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            nonce="developer_forged_nonce",
            admin_signature="bad" * 42,
            issued_at="2026-10-15T20:00:00Z"
        )
        fake_tx = EnrollmentTransaction(
            tx_id="forged_tx_" + str(uuid.uuid4())[:8],
            course_id="CS-801",
            student_public_key=fake_pubkey,
            encrypted_details=fake_student_name.encode('utf-8').hex(),
            iv_hex="00" * 12,
            tag_hex="00" * 16,
            invite_certificate=fake_invite,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            nonce="developer_injection_nonce",
            student_signature="bad" * 42
        )
        block.transactions.append(fake_tx)
        log_event("SECURITY", f"TAMPER SIMULATION: Injected unauthorized student '{fake_student_name}' into Block #{block_index}", level="WARN")
        return {
            "success": True,
            "action": "inject_unauthorized_student",
            "block_index": block_index,
            "fake_student": fake_student_name,
            "message": f"Injected unauthorized student '{fake_student_name}' into Block #{block_index}."
        }

    def simulate_corrupt_block_header(self, block_index: int) -> Dict[str, Any]:
        if block_index <= 0 or block_index >= len(self.chain):
            return {"success": False, "error": f"Invalid block index {block_index}"}
        block = self.chain[block_index]
        old_hash = block.header.block_hash
        corrupted = old_hash[:-2] + ("ff" if not old_hash.endswith("ff") else "00")
        block.header.block_hash = corrupted
        log_event("SECURITY", f"TAMPER SIMULATION: Corrupted Block #{block_index} header hash", level="WARN")
        return {
            "success": True,
            "action": "corrupt_block_header",
            "block_index": block_index,
            "old_hash": old_hash,
            "corrupted_hash": corrupted,
            "message": f"Corrupted Block #{block_index} header hash."
        }

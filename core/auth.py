import os
import hashlib
import uuid
import datetime
from typing import Dict, Optional, Tuple
from core.models import UserRegister, UserLogin, UserProfile
from core.crypto_engine import generate_ecdsa_keypair, sha256_str, encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
from core.logger import log_event

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if not salt:
        salt = os.urandom(16).hex()
    pwd_bytes = password.encode('utf-8')
    salt_bytes = bytes.fromhex(salt)
    # PBKDF2 with 100,000 iterations of SHA-256
    key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return key.hex(), salt

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    computed_hash, _ = hash_password(password, salt)
    return computed_hash.lower() == expected_hash.lower()

class UserRecord:
    def __init__(self, user_id: str, email: str, name: str, role: str, 
                 pwd_hash: str, salt: str, pub_key: str, priv_key: str, created_at: str):
        self.user_id = user_id
        self.email = email.lower().strip()
        self.name = name
        self.role = role.lower().strip()
        self.pwd_hash = pwd_hash
        self.salt = salt
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.identity_hash = sha256_str(pub_key)
        self.created_at = created_at

    def to_profile(self) -> UserProfile:
        return UserProfile(
            user_id=self.user_id,
            email=self.email,
            name=self.name,
            role=self.role,
            public_key=self.pub_key,
            identity_hash=self.identity_hash,
            created_at=self.created_at
        )

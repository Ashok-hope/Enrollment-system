import json
import hashlib
import os
from typing import List, Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

def canonical_json(data: Any) -> bytes:
    """Produce deterministic canonical JSON bytes (RFC 8785 style)."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hexadecimal string of given bytes."""
    return hashlib.sha256(data).hexdigest()

def sha256_str(text: str) -> str:
    """Compute SHA-256 hex of a string."""
    return sha256_hex(text.encode('utf-8'))

# =====================================================================
# MERKLE TREE IMPLEMENTATION
# =====================================================================

class MerkleTree:
    def __init__(self, tx_hashes: List[str]):
        self.tx_hashes = tx_hashes
        self.tree_levels: List[List[str]] = []
        self.root = self._build_tree()

    def _build_tree(self) -> str:
        if not self.tx_hashes:
            return sha256_hex(b"EMPTY_MERKLE_TREE")
        
        current_level = [h for h in self.tx_hashes]
        self.tree_levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = (left + right).encode('utf-8')
                parent_hash = sha256_hex(combined)
                next_level.append(parent_hash)
            current_level = next_level
            self.tree_levels.append(current_level)

        return current_level[0]

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        proof = []
        if index < 0 or index >= len(self.tx_hashes):
            return proof

        idx = index
        for level in self.tree_levels[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else (idx + 1 if idx + 1 < len(level) else idx)
            proof.append({
                "position": "left" if is_right else "right",
                "hash": level[sibling_idx]
            })
            idx = idx // 2
        return proof

    @staticmethod
    def verify_proof(tx_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        current = tx_hash
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "left":
                combined = (sibling + current).encode('utf-8')
            else:
                combined = (current + sibling).encode('utf-8')
            current = sha256_hex(combined)
        return current.lower() == expected_root.lower()

# =====================================================================
# ASYMMETRIC CRYPTOGRAPHY (ECDSA SECP256R1 / P-256)
# =====================================================================

def generate_ecdsa_keypair() -> Tuple[str, str]:
    """
    Generate an ECDSA (P-256) keypair returning (public_key_hex, private_key_hex).
    Exports PKCS#8 DER format for private key so WebCrypto imports cleanly without errors.
    """
    priv_key = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return pub_bytes.hex(), priv_bytes.hex()

def sign_data_ecdsa(private_key_hex: str, data_bytes: bytes) -> str:
    """Sign arbitrary data with ECDSA P-256 private key, returning IEEE P1363 raw (r, s) 64-byte hex."""
    clean_hex = private_key_hex.strip().replace("0x", "")
    priv_bytes = bytes.fromhex(clean_hex)
    
    if len(priv_bytes) == 32:
        priv_int = int(clean_hex, 16)
        priv_key = ec.derive_private_key(priv_int, ec.SECP256R1())
    else:
        priv_key = serialization.load_der_private_key(priv_bytes, password=None)
    
    der_signature = priv_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    return (r_bytes + s_bytes).hex()

def verify_signature_ecdsa(public_key_hex: str, data_bytes: bytes, signature_hex: str) -> bool:
    """Verify an ECDSA P-256 signature against public key hex and data bytes."""
    try:
        clean_pub = public_key_hex.strip().replace("0x", "")
        clean_sig = signature_hex.strip().replace("0x", "")
        pub_bytes = bytes.fromhex(clean_pub)
        sig_bytes = bytes.fromhex(clean_sig)
        
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        
        if len(sig_bytes) == 64:
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = sig_bytes
            
        pub_key.verify(der_sig, data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

# =====================================================================
# SYMMETRIC ENCRYPTION (AES-256-GCM)
# =====================================================================

def encrypt_payload_aes_gcm(plaintext: str, key_hex: str) -> Dict[str, str]:
    key = bytes.fromhex(key_hex)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return {
        "ciphertext_hex": ciphertext.hex(),
        "iv_hex": iv.hex(),
        "tag_hex": tag.hex()
    }

def decrypt_payload_aes_gcm(ciphertext_hex: str, iv_hex: str, tag_hex: str, key_hex: str) -> Optional[str]:
    try:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        tag = bytes.fromhex(tag_hex)
        ct = bytes.fromhex(ciphertext_hex)
        
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ct + tag, None)
        return decrypted.decode('utf-8')
    except Exception:
        return None

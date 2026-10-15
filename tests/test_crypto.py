import pytest
from core.crypto_engine import (
    generate_ecdsa_keypair, sign_data_ecdsa, verify_signature_ecdsa,
    sha256_str, sha256_hex, MerkleTree, encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
)

def test_ecdsa_keypair_and_signatures():
    pub_hex, priv_hex = generate_ecdsa_keypair()
    assert len(pub_hex) > 0
    assert len(priv_hex) > 0

    message = b"Course Enrollment Cryptographic Proof"
    signature = sign_data_ecdsa(priv_hex, message)
    assert len(signature) == 128 # 64 bytes in hex

    # Positive verification
    assert verify_signature_ecdsa(pub_hex, message, signature) is True

    # Tampered message should fail
    tampered_message = b"Course Enrollment Cryptographic Proof (Tampered)"
    assert verify_signature_ecdsa(pub_hex, tampered_message, signature) is False

    # Forged signature should fail
    bad_signature = "00" * 64
    assert verify_signature_ecdsa(pub_hex, message, bad_signature) is False

def test_merkle_tree_construction_and_proofs():
    txs = [f"tx_hash_{i}" for i in range(4)]
    tree = MerkleTree(txs)
    root = tree.root
    assert len(root) == 64

    # Proof for index 2
    proof = tree.get_proof(2)
    assert len(proof) == 2
    assert MerkleTree.verify_proof(txs[2], proof, root) is True

    # Bad tx hash should fail proof
    assert MerkleTree.verify_proof("fake_tx_hash", proof, root) is False

def test_aes_gcm_encryption_decryption():
    key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    secret_data = "Student Real Name: Alice Wonderland, Student ID: 2026-CS-409"

    enc = encrypt_payload_aes_gcm(secret_data, key_hex)
    assert "ciphertext_hex" in enc
    assert "iv_hex" in enc
    assert "tag_hex" in enc

    decrypted = decrypt_payload_aes_gcm(enc["ciphertext_hex"], enc["iv_hex"], enc["tag_hex"], key_hex)
    assert decrypted == secret_data

    # Tampering with ciphertext fails auth tag
    corrupted_ct = enc["ciphertext_hex"][:-2] + "ff"
    assert decrypt_payload_aes_gcm(corrupted_ct, enc["iv_hex"], enc["tag_hex"], key_hex) is None

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from core.models import Block, AuditReport
from core.crypto_engine import MerkleTree
from backend.database import db

router = APIRouter(prefix="/ledger", tags=["Blockchain Ledger"])

@router.get("/blocks", response_model=List[Block])
def get_blocks():
    return db.ledger.chain

@router.get("/block/{index}", response_model=Block)
def get_block(index: int):
    if index < 0 or index >= len(db.ledger.chain):
        raise HTTPException(status_code=404, detail="Block not found")
    return db.ledger.chain[index]

@router.get("/audit", response_model=AuditReport)
def run_ledger_audit():
    return db.ledger.audit_ledger(db.courses)

@router.get("/proof/{block_index}/{tx_id}")
def get_merkle_proof(block_index: int, tx_id: str):
    if block_index < 0 or block_index >= len(db.ledger.chain):
        raise HTTPException(status_code=404, detail="Block not found")
    
    block = db.ledger.chain[block_index]
    tx_hashes = [t.tx_id for t in block.transactions]
    if tx_id not in tx_hashes:
        raise HTTPException(status_code=404, detail="Transaction not found in specified block")
    
    tx_index = tx_hashes.index(tx_id)
    tree = MerkleTree(tx_hashes)
    proof = tree.get_proof(tx_index)
    
    return {
        "block_index": block_index,
        "tx_id": tx_id,
        "merkle_root": block.header.merkle_root,
        "proof": proof,
        "is_valid": MerkleTree.verify_proof(tx_id, proof, block.header.merkle_root)
    }

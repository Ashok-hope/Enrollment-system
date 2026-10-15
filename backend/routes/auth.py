from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from core.models import UserRegister, UserLogin, UserProfile
from backend.database import db

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register")
def register(payload: UserRegister):
    existing = db.get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    
    user = db.register_user(
        email=payload.email,
        password=payload.password,
        name=payload.name,
        role=payload.role
    )
    return {
        "success": True,
        "profile": user.to_profile(),
        "private_key": user.priv_key # Returned to client so the browser can hold it in session for signing
    }

@router.post("/login")
def login(payload: UserLogin):
    user = db.authenticate_user(payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    return {
        "success": True,
        "profile": user.to_profile(),
        "private_key": user.priv_key # Stored in sessionStorage on client for transparent digital signatures
    }

@router.get("/users", response_model=List[UserProfile])
def list_users():
    return [u.to_profile() for u in db.users.values()]

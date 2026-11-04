import os
from datetime import datetime, timezone, timedelta
import jwt
from jwt import InvalidTokenError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .db import get_db
from .models import User

hashing = PasswordHasher()
bearer = HTTPBearer()

def create_token(user: User) -> str:
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("Set JWT_SECRET to a random string of at least 32 characters")
    return jwt.encode({"sub": user.username, "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, secret, algorithm="HS256")

def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(creds.credentials, os.environ["JWT_SECRET"], algorithms=["HS256"])
        username = payload.get("sub")
    except (InvalidTokenError, KeyError):
        raise HTTPException(401, "Invalid or expired authentication token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(401, "Unknown user")
    return user

def admin_only(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    return user

def hash_password(s: str) -> str:
    return hashing.hash(s)

def verify_password(s: str, hash_value: str) -> bool:
    try:
        return hashing.verify(hash_value, s)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

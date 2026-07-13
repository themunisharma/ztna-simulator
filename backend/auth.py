# ============================================================
#  auth.py  —  Zero Trust Network Access Simulator
#  Handles: users, password hashing, JWT tokens, dependencies
# ============================================================

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── Config ──────────────────────────────────────────────────
SECRET_KEY = "zt-simulator-secret-key-change-in-production-2025"
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ── Password hashing ─────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ── Models ───────────────────────────────────────────────────
class User(BaseModel):
    username:        str
    full_name:       str
    email:           str
    role:            str   # admin | developer | intern | unknown
    trust_level:     int   # 0-100  (identity risk factor)
    department:      str
    hashed_password: str
    disabled:        bool = False

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    role:         str
    full_name:    str

class TokenData(BaseModel):
    username:    Optional[str] = None
    role:        Optional[str] = None
    trust_level: Optional[int] = None

class UserPublic(BaseModel):
    username:    str
    full_name:   str
    email:       str
    role:        str
    trust_level: int
    department:  str

# ── Seeded users ─────────────────────────────────────────────
USERS_DB: dict[str, User] = {
    "alice": User(
        username="alice", full_name="Alice Sharma",
        email="alice@company.com", role="admin", trust_level=95,
        department="IT Security", hashed_password=hash_password("admin@123"),
    ),
    "bob": User(
        username="bob", full_name="Bob Verma",
        email="bob@company.com", role="developer", trust_level=75,
        department="Engineering", hashed_password=hash_password("dev@123"),
    ),
    "charlie": User(
        username="charlie", full_name="Charlie Patel",
        email="charlie@company.com", role="intern", trust_level=40,
        department="HR", hashed_password=hash_password("intern@123"),
    ),
    "unknown_user": User(
        username="unknown_user", full_name="Unknown Entity",
        email="", role="unknown", trust_level=0,
        department="None", hashed_password=hash_password("unknown@123"),
    ),
}

# ── JWT helpers ───────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> TokenData:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise exc
        return TokenData(
            username=username,
            role=payload.get("role"),
            trust_level=payload.get("trust_level"),
        )
    except JWTError:
        raise exc

# ── User helpers ──────────────────────────────────────────────
def get_user(username: str) -> Optional[User]:
    return USERS_DB.get(username)

def authenticate_user(username: str, password: str) -> Optional[User]:
    user = get_user(username)
    if not user or user.disabled:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# ── FastAPI dependencies ──────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    token_data = decode_token(token)
    user = get_user(token_data.username)
    if user is None or user.disabled:
        raise HTTPException(status_code=401, detail="User not found or account disabled.")
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Account is disabled.")
    return current_user

async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail=f"Admin access required. Your role: {current_user.role}")
    return current_user

"""
Security utilities: password hashing, encryption, JWT
"""
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from typing import Optional
import jwt
import os
import secrets
import hashlib
import base64


# Password hashing
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=int(os.getenv("BCRYPT_ROUNDS", 12)))
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )


# JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token - long-lived unless explicitly logged out"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # Set to 10 years for persistent login (only logout on explicit action)
        expire = datetime.utcnow() + timedelta(days=3650)

    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token - long-lived unless explicitly logged out"""
    to_encode = data.copy()
    # Set to 10 years for persistent login (only logout on explicit action)
    expire = datetime.utcnow() + timedelta(days=3650)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


# Encryption (for API keys, secrets)
def get_encryption_key() -> bytes:
    """Get or generate encryption key"""
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise ValueError("ENCRYPTION_KEY not set")
    # Convert string to 32-byte key for Fernet
    key_bytes = key.encode()[:32].ljust(32, b'0')
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret using Fernet"""
    f = Fernet(get_encryption_key())
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a secret using Fernet"""
    f = Fernet(get_encryption_key())
    return f.decrypt(ciphertext.encode()).decode()


# API Key generation
def generate_api_key(prefix: str = "lead") -> tuple[str, str]:
    """Generate API key and return (full_key, key_hash)"""
    # Generate random key
    random_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}_live_{random_part}"
    
    # Hash for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = f"{prefix}_live_{random_part[:8]}"
    
    return full_key, key_hash, key_prefix


def hash_api_key(api_key: str) -> str:
    """Hash API key for comparison"""
    return hashlib.sha256(api_key.encode()).hexdigest()


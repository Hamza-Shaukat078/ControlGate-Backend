from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_token(subject: str | int, expires_minutes: int, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    to_encode: Dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    if extra_claims:
        to_encode.update(extra_claims)
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_access_token(subject: str | int, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    claims = {"token_type": "access"}
    if extra_claims:
        claims.update(extra_claims)
    return create_token(subject, settings.ACCESS_TOKEN_EXPIRE_MINUTES, claims)


def create_refresh_token(subject: str | int, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    claims = {"token_type": "refresh"}
    if extra_claims:
        claims.update(extra_claims)
    return create_token(subject, settings.REFRESH_TOKEN_EXPIRE_MINUTES, claims)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        return payload
    except JWTError as e:
        raise e

import time
import secrets
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set
import jwt

@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int

@dataclass
class JWTConfig:
    secret_key: str
    algorithm: str = "HS256"
    access_ttl: int = 900       # 15 min
    refresh_ttl: int = 604800   # 7 days
    issuer: str = "securegate"

class RevocationStore:
    """In-memory revocation store. Replace with Redis/DB for production clusters."""
    def __init__(self):
        self._revoked: Set[str] = set()

    def revoke(self, jti: str) -> None:
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

class RefreshTokenStore:
    """Tracks valid refresh tokens. Replace with Redis/DB for production clusters."""
    def __init__(self):
        self._tokens: dict = {}  # hashed_token -> (user_id, expires_at)

    def store(self, user_id: str, token: str, expires_at: float) -> None:
        h = hashlib.sha256(token.encode()).hexdigest()
        self._tokens[h] = (user_id, expires_at)

    def validate(self, token: str) -> Optional[str]:
        h = hashlib.sha256(token.encode()).hexdigest()
        entry = self._tokens.get(h)
        if not entry:
            return None
        user_id, expires_at = entry
        if time.time() > expires_at:
            del self._tokens[h]
            return None
        return user_id

    def revoke(self, token: str) -> None:
        h = hashlib.sha256(token.encode()).hexdigest()
        self._tokens.pop(h, None)

class JWTAuthMiddleware:
    def __init__(self, config: JWTConfig):
        self.config = config
        self.revocation_store = RevocationStore()
        self.refresh_store = RefreshTokenStore()

    def issue_tokens(self, user_id: str, roles: list = None, extra: dict = None) -> TokenPair:
        now = int(time.time())
        jti = secrets.token_urlsafe(16)
        payload = {
            "sub": user_id,
            "iat": now,
            "exp": now + self.config.access_ttl,
            "iss": self.config.issuer,
            "jti": jti,
            "type": "access",
            "roles": roles or [],
        }
        if extra:
            payload.update(extra)
        access_token = jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

        refresh_token = secrets.token_urlsafe(48)
        self.refresh_store.store(user_id, refresh_token, now + self.config.refresh_ttl)

        return TokenPair(access_token=access_token, refresh_token=refresh_token,
                         expires_in=self.config.access_ttl)

    def validate_access_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, self.config.secret_key,
                                 algorithms=[self.config.algorithm],
                                 issuer=self.config.issuer)
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")

        if payload.get("type") != "access":
            raise AuthenticationError("Not an access token")

        if self.revocation_store.is_revoked(payload["jti"]):
            raise AuthenticationError("Token has been revoked")

        return payload

    def refresh_tokens(self, refresh_token: str) -> TokenPair:
        user_id = self.refresh_store.validate(refresh_token)
        if not user_id:
            raise AuthenticationError("Invalid or expired refresh token")

        self.refresh_store.revoke(refresh_token)
        return self.issue_tokens(user_id)

    def revoke_access_token(self, token: str) -> None:
        payload = self.validate_access_token(token)
        self.revocation_store.revoke(payload["jti"])

    def revoke_refresh_token(self, refresh_token: str) -> None:
        self.refresh_store.revoke(refresh_token)

class AuthenticationError(Exception):
    pass
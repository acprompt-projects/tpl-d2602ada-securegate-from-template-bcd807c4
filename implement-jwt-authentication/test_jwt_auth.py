import time
import jwt
import pytest
from jwt_auth import JWTAuthMiddleware, JWTConfig, AuthenticationError

@pytest.fixture
def auth():
    return JWTAuthMiddleware(JWTConfig(secret_key="test-secret-key-min-32-chars!!"))

class TestTokenIssuance:
    def test_issue_returns_valid_pair(self, auth):
        pair = auth.issue_tokens("user1", roles=["admin"])
        assert pair.access_token and pair.refresh_token
        assert pair.expires_in == 900

    def test_access_token_contains_claims(self, auth):
        pair = auth.issue_tokens("user1", roles=["admin"], extra={"org": "acme"})
        payload = jwt.decode(pair.access_token, "test-secret-key-min-32-chars!!",
                             algorithms=["HS256"], issuer="securegate")
        assert payload["sub"] == "user1"
        assert payload["roles"] == ["admin"]
        assert payload["type"] == "access"
        assert payload["org"] == "acme"
        assert "jti" in payload

class TestTokenValidation:
    def test_valid_token_passes(self, auth):
        pair = auth.issue_tokens("user1")
        payload = auth.validate_access_token(pair.access_token)
        assert payload["sub"] == "user1"

    def test_expired_token_fails(self, auth):
        config = JWTConfig(secret_key="test-secret-key-min-32-chars!!", access_ttl=-1)
        bad_auth = JWTAuthMiddleware(config)
        pair = bad_auth.issue_tokens("user1")
        with pytest.raises(AuthenticationError, match="Invalid token"):
            bad_auth.validate_access_token(pair.access_token)

    def test_tampered_token_fails(self, auth):
        with pytest.raises(AuthenticationError):
            auth.validate_access_token("eyJhbGciOiJIUzI1NiJ9.fake.payload")

    def test_revoked_token_fails(self, auth):
        pair = auth.issue_tokens("user1")
        auth.revoke_access_token(pair.access_token)
        with pytest.raises(AuthenticationError, match="revoked"):
            auth.validate_access_token(pair.access_token)

    def test_refresh_token_rejected_as_access(self, auth):
        pair = auth.issue_tokens("user1")
        refresh_as_jwt = jwt.encode({"sub": "u", "type": "refresh", "iss": "securegate",
                                     "iat": int(time.time()), "exp": int(time.time())+9999},
                                    "test-secret-key-min-32-chars!!", algorithm="HS256")
        with pytest.raises(AuthenticationError, match="Not an access token"):
            auth.validate_access_token(refresh_as_jwt)

class TestRefreshRotation:
    def test_refresh_issues_new_pair(self, auth):
        pair = auth.issue_tokens("user1")
        new_pair = auth.refresh_tokens(pair.refresh_token)
        assert new_pair.access_token != pair.access_token
        assert new_pair.refresh_token != pair.refresh_token

    def test_old_refresh_rejected_after_rotation(self, auth):
        pair = auth.issue_tokens("user1")
        auth.refresh_tokens(pair.refresh_token)
        with pytest.raises(AuthenticationError):
            auth.refresh_tokens(pair.refresh_token)

    def test_invalid_refresh_rejected(self, auth):
        with pytest.raises(AuthenticationError):
            auth.refresh_tokens("garbage-token")

class TestRevocation:
    def test_explicit_refresh_revocation(self, auth):
        pair = auth.issue_tokens("user1")
        auth.revoke_refresh_token(pair.refresh_token)
        with pytest.raises(AuthenticationError):
            auth.refresh_tokens(pair.refresh_token)
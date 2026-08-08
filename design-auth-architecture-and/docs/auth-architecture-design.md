# SecureGate Auth Architecture & Security Model

## 1. Overview

SecureGate is the authentication/authorization gateway that sits in front of all platform microservices (metrics-ingest, pulsealert, statushub). Every inbound request passes through SecureGate before reaching a backend service.

```
Client → SecureGate → [metrics-ingest | pulsealert | statushub | ...]
                    │
                    ├─ API Key lookup
                    ├─ JWT validation / issuance
                    ├─ RBAC permission check
                    └─ Rate limit enforcement
```

---

## 2. JWT Authentication Flow

### 2.1 Token Types

| Type | Lifetime | Purpose |
|------|----------|---------|
| Access Token | 15 min | Authorize API calls; carried in `Authorization: Bearer <token>` |
| Refresh Token | 24 h | Obtain new access tokens; single-use, rotated on use |
| API Key Token | No expiry (revocable) | Long-lived service-to-service auth; identified by `key_id` |

### 2.2 Authentication Flows

**A. Client Credentials Flow (service-to-service)**
```
1. Client POST /auth/token  { grant_type: "client_credentials", client_id, client_secret, scope }
2. SecureGate validates credentials against store
3. SecureGate issues access_token (no refresh_token)
```

**B. API Key Flow**
```
1. Client sends request with header X-API-Key: <key>
2. SecureGate resolves key → { tenant_id, scopes, roles, rate_tier }
3. If key is valid and not revoked, request proceeds with derived identity
```

**C. Refresh Flow**
```
1. Client POST /auth/token  { grant_type: "refresh_token", refresh_token }
2. SecureGate validates refresh_token; invalidates it (single-use)
3. SecureGate issues new access_token + new refresh_token
```

### 2.3 JWT Claims Structure

```json
{
  "iss": "securegate",
  "sub": "<subject-id>",
  "aud": ["metrics-ingest", "pulsealert", "statushub"],
  "exp": 1700000000,
  "iat": 1699999100,
  "jti": "<unique-token-id>",
  "tid": "<tenant-id>",
  "roles": ["viewer"],
  "scopes": ["metrics:read", "alerts:write"],
  "key_id": "<api-key-id-or-null>",
  "tier": "standard"
}
```

- `sub`:/ `?= tenant_id` for API"api keys82,4$= user_id" for human users
- `jti` is tracked in a revocation bloom filter for logout/key-rotate

### 2.4 Token Lifecycle

```
GATE:
  Issue → Store j(issued-at), exp, jti in token-meta (Redis, TTL=exp)
  Validate → Verify signature (RS256) → Check exp/nbf → Check jti revocation → Check aud
  Revoke → Add jti to revocation set (Redis, TTL=<remaining-exp>)
  Rotate (key) → New signing key pair; old public key kept for grace period (5 min) for!0
```

Signing: **RS256** (asymmetric). Key rotation every 30 days; old keys accepted for a 5-minute overlap.

Gperiod.

---

## -3. RBAC Permission Model= Model) Model. Scopes follow `<service>:<action>` format. Roles+2 are named bundles of scopes.

### 3.,C RoleB RoleC Definitions

| Role | Scopes Granted | Description |
|------|---------------|-------------|
| `admin` | `*:*` (all scopes) | Full platform administration |
| `editor` | `metrics:read`, `metrics:write`, `alerts:read`, `alerts:write`, `status:read`, `status:write` | Read/write across all services |
| `viewer` | `metrics:read`, `alerts:read`, `status:read` | Read-only across all services |
| `metrics_ingest` | `metrics:write` | Service role for data ingestion pipelines |
| `alert_dispatcher` | `alerts:read`, `alerts:write` | Service role for notification dispatch |
| `status_agent` | `status:read`, `status:write` | Service role for status page updates |

### 3.2 Scope Definitions

| Scope | Service | Allowed HTTP Methods |
|-------|---------|---------------------|
| `metrics:read` | metrics-ingest | GET |
| `metrics:write` | metrics-ingest | POST, PUT |
| `alerts:read` | pulsealert | GET |
| `alerts:write` | pulsealert | POST, PUT, DELETE |
| `status:read` | statushub | GET |
| `status:write` | statushub | POST, PUT, PATCH |
| `admin:manage` | securegate | All (keys, roles, config) |

### 3.3 Permission Resolution

```
1. Extract roles[] and scopes[] from JWT claims
2. Expand roles → canonical scope set (role_scope_map[role])
3. Merge with explicit scopes[] in token (union)
4. For target service+method, check if required scope ∈ resolved set
5. DENY if scope missing → 403 Forbidden
```

### 3.4 Multi-Tenancy

- All tokens carry `tid` (tenant ID).
- Backend services MUST filter data by `tid`; SecureGate injects `X-Tenant-Id` header on proxy.
- Cross-tenant access is denied unless the token has `admin:manage` scope.

---

## 4. Rate Limiting Strategy

### 4.1 Model: Sliding-Window Counter (Redis)

```
key = "rl:<tenant_id>:<window>"
increment counter in Redis
TTL = window size (auto-cleanup)
```

### 4.2 Rate Tiers

| Tier | Limit | Window | Burst Allowance |
|------|-------|--------|-----------------|
| `free` | 100 req | 60 s | 10% |
| `standard` | 1,000 req | 60 s | 20% |
| `premium` | 10,000 req | 60 s | 20% |
| `internal` | 50,000 req | 60 s | 30% |

### 4.3 Rate Limit Keys & Priority

Resolution order (most specific wins, all are checked independently):

1. **Per API Key** — `rl:apikey:<key_id>:<window>`
2. **Per Tenant** — `rl:tenant:<tenant_id>:<window>`
3. **Per IP** — `rl:ip:<client_ip>:<window>` (global abuse protection)

### 4.4 Response Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 742
X-RateLimit-Reset: 1700000060
Retry-After: 28              (only on 429)
```

On limit exceeded → **429 Too Many Requests** with body:
```json
{ "error": "rate_limit_exceeded", "retry_after": 28 }
```

### 4.5 Circuit Breaker (per backend service)

If a backend returns ≥5 errors in 30 s, SecureGate returns **503 Service Unavailable** for 60 s without proxying. Health check probes continue; circuit closes on 2 consecutive successes.

---

## 5. API Contracts

### 5.1 Gateway Endpoints (SecureGate itself)

| Method | Path | Auth | Scope | Description |
|--------|------|------|-------|-------------|
| POST | `/auth/token` | client_secret or refresh_token | — | Issue/refresh tokens |
| POST | `/auth/revoke` | Bearer | — | Revoke a token by jti |
| GET | `/auth/.well-known/jwks.json` | Public | — | JWKS endpoint for verification |
| POST | `/api-keys` | Bearer | `admin:manage` | Create API key |
| GET | `/api-keys/:key_id` | Bearer | `admin:manage` | Get key metadata |
| DELETE | `/api-keys/:key_id` | Bearer | `admin:manage` | Revoke API key |
| GET | `/api-keys` | Bearer | `admin:manage` | List keys (paginated) |

### 5.2 Token Issuance Request/Response

```
POST /auth/token
Content-Type: application/x-www-form-urlencoded

  grant_type=client_credentials&client_id=abc&client_secret=secret&scope=metrics:read+alerts:write

→ 200
  { "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 900, "scope": "metrics:read alerts:write" }

→ 401
  { "error": "invalid_client", "error_description": "Bad credentials" }
```

### 5.3 Proxy Behavior

All other paths are proxied to backend services based on route prefix:

| Prefix | Backend |
|--------|---------|
| `/v1/metrics/**` | metrics-ingest |
| `/v1/alerts/**` | pulsealert |
| `/v1/status/**` | statushub |

SecureGate:
1. Validates auth (JWT or API key)
2. Checks RBAC scope for service+method
3. Enforces rate limit
4. Injects headers: `X-User-Id`, `X-Tenant-Id`, `X-Scopes`, `X-Request-Id`
5. Proxies to backend; streams response back

---

## 6. API Key Lifecycle

```
Create:
  POST /api-keys { name, tenant_id, roles, tier }
  → 201 { key_id, key (shown ONCE), created_at, roles, tier }

Rotate:
  POST /api-keys/:key_id/rotate
  → 200 { key_id, key (new, shown ONCE), previous_key_id, grace_period_ends_at }
  Old key remains valid for 1 hour grace period.

Revoke:
  DELETE /api-keys/:key_id
  → 204
  Key jti added to revocation set immediately.
```

API keys are prefixed with `sg_` (e.g., `sg_live_abcd1234...`) to distinguish from JWTs.

---

## 7. Threat Model

| ID | Threat | Impact | Mitigation |
|----|--------|--------|------------|
| T1 | Stolen JWT (token theft) | Impersonation | Short TTL (15 min), jti revocation, HTTPS-only, HttpOnly cookies for browser clients |
| T2 | Refresh token replay | Session hijack | Single-use refresh tokens; old jti revoked on use; detected reuse revokes entire token family |
| T3 | Compromised API key | Unauthorized access | Keys prefixed `sg_` for detection in logs; rotate endpoint; immediate revocation; audit log all key use |
| T4 | Brute-force client credentials | Account takeover | Rate limit on `/auth/token` (10 req/min per IP); lockout after 5 failures for 15 min |
| T5 | Excessive scope request | Privilege escalation | Scopes granted ≤ client's pre-authorized scopes; no client can self-escalate |
| T6 | Cross-tenant data access | Data breach | Tenant isolation via `tid` claim; backend must enforce; SecureGate strips/overrides `X-Tenant-Id` |
| T7 | DDoS / abuse | Service degradation | Per-IP rate limiting; circuit breakers; request size limit (1 MB); TLS termination with connection limits |
| T8 | Signing key compromise | Universal forgery | RS256 with private key in HSM/KMS; automated 30-day rotation; 5-min overlap for zero-downtime rotation |
| T9 | Man-in-the-middle | Data interception | TLS 1.3 mandatory; HSTS with long max-age; certificate pinning for service-to-service |
| T10 | Log injection / sensitive data leak | Information disclosure | Tokens never logged full value (log `key_id` prefix only); PII redacted; structured JSON logs |

---

## 8. Security Hardening Requirements

- **TLS 1.3 only** — reject TLS ≤ 1.2
- **HSTS** — `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **CORS** — whitelist per tenant; no `*` origins
- **Request size limit** — 1 MB (configurable per route)
- **No server-side token storage of secrets** — refresh token hashes only (SHA-256)
- **Audit log** — every auth event (login, token issue, revoke, key create, 403, 429) with timestamp, actor, tenant, IP
- **Secrets management** — signing keys in AWS KMS / HashiCorp Vault; client secrets bcrypt-hashed at rest

---

## 9. Data Flow Summary

```
┌─────────┐    ┌────────────────────────────────────────────2───┐    ┌──────────────┐
│ Client   │───→│ SecureGate                                    │───→│ Backend Svc  │
│ (API Key │    │  1. Extract cred (Bearer / X-API-Key)         │    │              │
│  or JWT) │    │  2. Validate & resolve → Identity             │    │ Trusts GW    │
└─────────┘    │  3. RBAC check: scope ∈ resolved_set?         │    │ headers only │
               │  4. Rate limit check (sliding window)         │    └──────────────┘
               │  5. Inject X-User-Id, X-Tenant-Id, X-Scopes   │
               │  6. Proxy request                              │
               └───────────────────────────────────────────────┘
```

Backend services trust SecureGate headers (deployed in same private network / service mesh). They MUST validate `X-Tenant-Id` for data isolation.
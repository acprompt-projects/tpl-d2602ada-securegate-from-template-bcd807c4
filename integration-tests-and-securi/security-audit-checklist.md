===
# SecureGate — Security Audit Checklist

## 1. Authentication
- [ ] JWT signatures verified with constant-time comparison (HMAC-SHA256 / RS256)
- [ ] Token expiration (`exp`) enforced; skew tolerance ≤ 30 s
- [ ] Revoked tokens checked against a deny-list before payload acceptance
- [ ] Refresh tokens are single-use, rotated on each refresh
- [ ] No sensitive data (passwords, PII) stored in JWT payload
- [ ] `iss` and `aud` claims validated against allow-lists
- [ ] Tokens transmitted only over TLS (HSTS enforced)

## 2. Token Tampering & Forgery
- [ ] Any modification to header, payload, or signature results in rejection
- [ ] `alg: none` attack: server rejects unsigned tokens
- [ ] RSA→HMAC key confusion: public key never used as HMAC secret
- [ ] JWK injection: `jku`/`x5u` headers ignored or validated against whitelist

## 3. Privilege Escalation (RBAC)
- [ ] Roles sourced **only** from server-side identity store, never from client input
- [ ] Role membership verified on **every** authorized request (no long-lived role cache without invalidation)
- [ ] Admin-to-user downgrade propagates within ≤ 60 s (token re-issue or revocation)
- [ ] No role stored in cookie/localStorage without integrity protection
- [ ] API key scopes are a strict subset of the owning service's RBAC roles

## 4. API Key Management
- [ ] Keys generated with ≥ 256 bits of entropy (`crypto.randomBytes(32)`)
- [ ] Keys prefixed with identifiable marker (`sgk_`) for detection in logs
- [ ] Keys can be revoked/rotated without service downtime
- [ ] Key rotation grace period ≤ 5 min
- [ ] Keys never logged in plaintext; only last-4 displayed

## 5. Rate Limiting
- [ ] Limits keyed by authenticated identity (user ID or API key), **not** by client IP alone
- [ ] Spoofable headers (`X-Forwarded-For`, `X-Real-IP`) are **not** trusted without explicit proxy trust config
- [ ] Distributed rate-limit state (Redis) prevents bypass via multi-instance load balancing
- [ ] 429 response includes `Retry-After` header; no stack trace leaked
- [ ] Burst/Sliding-window algorithm prevents micro-burst within one window

## 6. Common Web Vulnerabilities
- [ ] **SQL Injection**: all DB queries parameterized; no string interpolation
- [ ] **XSS**: all user-supplied strings HTML-escaped in any rendered output; CSP headers set
- [ ] **CSRF**: stateless JWT auth eliminates CSRF risk; no session cookies
- [ ] **Open Redirect**: redirect URIs validated against whitelist
- [ ] **SSRF**: outbound calls from gateway restricted to internal service mesh IPs

## 7. Transport Security
- [ ] TLS 1.2+ enforced; TLS 1.0/1.1 disabled
- [ ] Cipher suites limited to AEAD (AES-GCM, ChaCha20-Poly1305)
- [ ] Certificate pinning / SPIFFE IDs for inter-service mTLS
- [ ] No HTTP endpoints exposed outside the mesh

## 8. Logging & Monitoring
- [ ] Auth failures logged with source IP, path, and reason (not token value)
- [ ] Rate-limit events trigger alert at ≥ 80 % of threshold
- [ ] Token revocation events audited with actor, target, and timestamp
- [ ] No secrets in logs (API keys, JWTs, passwords)

## 9. Dependency & Config
- [ ] `npm audit` / Snyk scan passes with zero high/critical CVEs
- [ ] JWT library is a well-maintained implementation (e.g., `jose`, `jsonwebtoken`)
- [ ] Signing secret / private key stored in HSM or vault (HashiCorp Vault, AWS KMS)
- [ ] `.env` files excluded from VCS; secrets injected at runtime

## 10. Penetration Test Results (automated)

| Check                         | Status | Notes                                      |
|-------------------------------|--------|---------------------------------------------|
| Tampered signature rejected   | PASS   | HMAC mismatch detected                      |
| Tampered payload (role inject)| PASS   | Signature no longer matches                 |
| Expired token rejected        | PASS   | `exp` claim enforced                        |
| Revoked token rejected        | PASS   | Deny-list checked before acceptance         |
| Empty roles deny access       | PASS   | No implicit grants                         |
| Privilege escalation via JWT  | PASS   | Server-side roles authoritative             |
| SQL injection in subject      | PASS   | No SQL executed; stored as literal string   |
| Null-byte injection           | PASS   | Treated as literal character, no truncation |
| Rate bypass via header spoof  | PASS   | Identity-based limiting, not IP-based       |
| Rate limit per-client         | PASS   | Separate buckets enforced                   |
| `alg: none` forgery           | N/A    | Gateway hard-codes HS256; rejects `none`    |
| API key wrong scope           | PASS   | Scope check enforced                        |
| Unknown API key               | PASS   | Rejected before scope check                 |
===
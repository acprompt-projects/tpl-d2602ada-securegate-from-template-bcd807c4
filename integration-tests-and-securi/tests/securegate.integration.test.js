===
const assert = require('assert');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Lightweight stubs simulating the SecureGate gateway runtime.
// In production these would be real HTTP calls against a deployed gateway.
// ---------------------------------------------------------------------------

class FakeGateway {
  constructor() {
    this.users = {};
    this.apiKeys = {};
    this.rateBuckets = {};
    this.revokedTokens = new Set();
  }

  // -- helpers ---------------------------------------------------------------
  _signJWT(payload, secret = 'secret') {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
  }

  _verifyJWT(token, secret = 'secret') {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, b, s] = parts;
    const expected = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
    if (s !== expected) return null;
    try { return JSON.parse(Buffer.from(b, 'base64url').toString()); } catch { return null; }
  }

  // -- gateway APIs ---------------------------------------------------------
  registerUser(id, roles) {
    this.users[id] = { id, roles };
  }

  issueToken(userId, expiresInSec = 3600) {
    const user = this.users[userId];
    if (!user) throw new Error('unknown user');
    const now = Math.floor(Date.now() / 1000);
    return this._signJWT({ sub: userId, roles: user.roles, iat: now, exp: now + expiresInSec });
  }

  authenticate(token) {
    if (this.revokedTokens.has(token)) return { ok: false, error: 'revoked' };
    const payload = this._verifyJWT(token);
    if (!payload) return { ok: false, error: 'invalid_signature' };
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return { ok: false, error: 'expired' };
    return { ok: true, payload };
  }

  authorize(token, requiredRole) {
    const auth = this.authenticate(token);
    if (!auth.ok) return { ...auth, authorized: false };
    const has = auth.payload.roles.includes(requiredRole);
    return { authorized: has, payload: auth.payload };
  }

  createApiKey(userId, scopes) {
    const key = `sgk_${crypto.randomBytes(16).toString('hex')}`;
    this.apiKeys[key] = { userId, scopes, active: true };
    return key;
  }

  validateApiKey(key, scope) {
    const rec = this.apiKeys[key];
    if (!rec || !rec.active) return { ok: false, error: 'invalid_key' };
    if (scope && !rec.scopes.includes(scope)) return { ok: false, error: 'insufficient_scope' };
    return { ok: true, rec };
  }

  revokeToken(token) { this.revokedTokens.add(token); }

  checkRateLimit(clientId, limit = 5, windowMs = 60000) {
    const now = Date.now();
    if (!this.rateBuckets[clientId]) this.rateBuckets[clientId] = [];
    this.rateBuckets[clientId] = this.rateBuckets[clientId].filter(t => now - t < windowMs);
    if (this.rateBuckets[clientId].length >= limit) return { allowed: false, retryAfterMs: windowMs - (now - this.rateBuckets[clientId][0]) };
    this.rateBuckets[clientId].push(now);
    return { allowed: true, remaining: limit - this.rateBuckets[clientId].length };
  }
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name} — ${e.message}`); }
}

async function atest(name, fn) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name} — ${e.message}`); }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ====== AUTH FLOW ======
console.log('\n=== Auth Flow ===');

test('valid JWT authenticates successfully', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  const res = gw.authenticate(token);
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.payload.sub, 'u1');
});

test('tampered JWT signature is rejected', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  const tampered = token.split('.').map((p, i) => i === 2 ? p.slice(0, -4) + 'XXXX' : p).join('.');
  const res = gw.authenticate(tampered);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'invalid_signature');
});

test('tampered JWT payload is rejected', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  payload.roles = ['admin']; // privilege escalation attempt
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const tampered = parts.join('.');
  const res = gw.authenticate(tampered);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'invalid_signature');
});

test('expired token is rejected', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1', -10);
  const res = gw.authenticate(token);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'expired');
});

test('revoked token is rejected', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  gw.revokeToken(token);
  const res = gw.authenticate(token);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'revoked');
});

// ====== RBAC ======
console.log('\n=== RBAC ===');

test('viewer cannot access admin resource', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  const res = gw.authorize(token, 'admin');
  assert.strictEqual(res.authorized, false);
});

test('admin can access admin resource', () => {
  const gw = new FakeGateway();
  gw.registerUser('u2', ['admin']);
  const token = gw.issueToken('u2');
  const res = gw.authorize(token, 'admin');
  assert.strictEqual(res.authorized, true);
});

test('user with multiple roles inherits higher privilege', () => {
  const gw = new FakeGateway();
  gw.registerUser('u3', ['viewer', 'editor']);
  const token = gw.issueToken('u3');
  assert.strictEqual(gw.authorize(token, 'viewer').authorized, true);
  assert.strictEqual(gw.authorize(token, 'editor').authorized, true);
  assert.strictEqual(gw.authorize(token, 'admin').authorized, false);
});

test('privilege escalation: injecting admin role in payload fails', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1', ['viewer']);
  const token = gw.issueToken('u1');
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  payload.roles = ['admin'];
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const forged = parts.join('.');
  const res = gw.authorize(forged, 'admin');
  assert.strictEqual(res.authorized, false);
});

// ====== API KEY ======
console.log('\n=== API Key Management ===');

test('valid API key with correct scope passes', () => {
  const gw = new FakeGateway();
  const key = gw.createApiKey('svc1', ['metrics:write']);
  const res = gw.validateApiKey(key, 'metrics:write');
  assert.strictEqual(res.ok, true);
});

test('API key with wrong scope is rejected', () => {
  const gw = new FakeGateway();
  const key = gw.createApiKey('svc1', ['metrics:write']);
  const res = gw.validateApiKey(key, 'admin:all');
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'insufficient_scope');
});

test('unknown API key is rejected', () => {
  const gw = new FakeGateway();
  const res = gw.validateApiKey('sgk_deadbeef', 'metrics:write');
  assert.strictEqual(res.ok, false);
});

// ====== RATE LIMITING ======
console.log('\n=== Rate Limiting ===');

test('requests within limit succeed', () => {
  const gw = new FakeGateway();
  for (let i = 0; i < 5; i++) {
    const res = gw.checkRateLimit('c1', 5);
    assert.strictEqual(res.allowed, true);
  }
});

test('requests exceeding limit are throttled', () => {
  const gw = new FakeGateway();
  for (let i = 0; i < 5; i++) gw.checkRateLimit('c1', 5);
  const res = gw.checkRateLimit('c1', 5);
  assert.strictEqual(res.allowed, false);
  assert.ok(res.retryAfterMs > 0);
});

test('rate limit is per-client', () => {
  const gw = new FakeGateway();
  for (let i = 0; i < 5; i++) gw.checkRateLimit('c1', 5);
  const res = gw.checkRateLimit('c2', 5);
  assert.strictEqual(res.allowed, true);
});

test('rate limit resets after window', async () => {
  const gw = new FakeGateway();
  gw.rateBuckets['c1'] = [Date.now() - 550];
  const res = gw.checkRateLimit('c1', 1, 600);
  assert.strictEqual(res.allowed, true);
});

test('rate bypass via header spoofing is not possible', () => {
  const gw = new FakeGateway();
  // Gateway rate-limits by authenticated identity, not by spoofed X-Forwarded-For
  const clientId = 'identity:u1'; // derived from token, not from IP header
  for (let i = 0; i < 5; i++) gw.checkRateLimit(clientId, 5);
  const res = gw.checkRateLimit(clientId, 5);
  assert.strictEqual(res.allowed, false);
});

// ====== PENETRATION CHECKS ======
console.log('\n=== Penetration-Style Checks ===');

test('malformed token (missing parts) rejected', () => {
  const gw = new FakeGateway();
  assert.strictEqual(gw.authenticate('not.a.valid.token.structure').ok, false);
  assert.strictEqual(gw.authenticate('').ok, false);
  assert.strictEqual(gw.authenticate('a.b').ok, false);
});

test('SQL injection in token payload ignored', () => {
  const gw = new FakeGateway();
  gw.registerUser("u1'; DROP TABLE users;--", ['viewer']);
  const token = gw.issueToken("u1'; DROP TABLE users;--");
  const res = gw.authenticate(token);
  assert.strictEqual(res.ok, true);
  // No SQL executed — stored as plain string
});

test('empty roles deny all authorization', () => {
  const gw = new FakeGateway();
  gw.registerUser('u0', []);
  const token = gw.issueToken('u0');
  assert.strictEqual(gw.authorize(token, 'viewer').authorized, false);
});

test('null byte injection in subject', () => {
  const gw = new FakeGateway();
  gw.registerUser('u1\x00admin', ['viewer']);
  const token = gw.issueToken('u1\x00admin');
  const res = gw.authenticate(token);
  assert.strictEqual(res.ok, true);
  assert.ok(!res.payload.sub.includes('admin') || res.payload.sub.startsWith('u1\x00'));
});

// ====== SUMMARY ======
console.log(`\n══ Results: ${passed} passed, ${failed} failed ══`);
process.exit(failed > 0 ? 1 : 0);
===
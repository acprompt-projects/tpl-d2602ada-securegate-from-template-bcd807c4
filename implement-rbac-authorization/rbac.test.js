const assert = require('assert');
const { RBAC, DEFAULT_HIERARCHY } = require('./rbac');

// Minimal request/response mocks
function mockReq(user) {
  return { user, rbac: null };
}
function mockRes() {
  let status, body;
  return {
    status(s) { status = s; return this; },
    json(b) { body = b; return this; },
    getStatus: () => status,
    getBody: () => body,
  };
}

function run() {
  const rbac = new RBAC();
  let passed = 0;

  // 1. Role hierarchy: viewer has base permissions
  const vp = rbac.getPermissions('viewer');
  assert(vp.has('alerts:read'), 'viewer should have alerts:read');
  assert(vp.has('status:read'), 'viewer should have status:read');
  assert(!vp.has('alerts:write'), 'viewer should NOT have alerts:write');
  passed++;

  // 2. Permission inheritance: editor inherits viewer perms
  const ep = rbac.getPermissions('editor');
  assert(ep.has('alerts:read'), 'editor inherits alerts:read');
  assert(ep.has('alerts:write'), 'editor has alerts:write');
  assert(!ep.has('users:delete'), 'editor should NOT have users:delete');
  passed++;

  // 3. Admin inherits editor+viewer
  const ap = rbac.getPermissions('admin');
  assert(ap.has('users:delete'), 'admin has users:delete');
  assert(ap.has('alerts:write'), 'admin inherits alerts:write');
  assert(ap.has('status:read'), 'admin inherits status:read');
  passed++;

  // 4. Superadmin wildcard
  assert(rbac.hasPermission('superadmin', 'anything:whatever'), 'superadmin wildcard');
  passed++;

  // 5. Resource wildcard
  const customHierarchy = [
    { role: 'root', inherits: null, permissions: ['alerts:*'] },
  ];
  const customRbac = new RBAC(customHierarchy);
  assert(customRbac.hasPermission('root', 'alerts:read'), 'resource wildcard match');
  assert(!customRbac.hasPermission('root', 'users:read'), 'resource wildcard no cross');
  passed++;

  // 6. Unknown role
  assert.strictEqual(rbac.getPermissions('ghost').size, 0, 'unknown role returns empty');
  passed++;

  // 7. Middleware: authorized
  const mw = rbac.authorize('alerts:read');
  const req = mockReq({ id: 'u1', role: 'viewer' });
  const res = mockRes();
  let called = false;
  mw(req, res, () => { called = true; });
  assert(called, 'middleware should call next()');
  assert.deepStrictEqual(req.rbac.checked, 'alerts:read');
  passed++;

  // 8. Middleware: forbidden (insufficient perm)
  const mw2 = rbac.authorize('alerts:write');
  const req2 = mockReq({ id: 'u2', role: 'viewer' });
  const res2 = mockRes();
  mw2(req2, res2, () => {});
  assert.strictEqual(res2.getStatus(), 403);
  passed++;

  // 9. Middleware: unauthenticated (no user)
  const req3 = mockReq(null);
  const res3 = mockRes();
  mw2(req3, res3, () => {});
  assert.strictEqual(res3.getStatus(), 401);
  passed++;

  // 10. Policy-based deny
  const rbacP = new RBAC();
  rbacP.addPolicy({ resource: 'users', action: 'delete', deny: ['editor'] });
  const mwP = rbacP.authorize('users:delete');
  const reqP = mockReq({ id: 'u3', role: 'editor' });
  const resP = mockRes();
  mwP(reqP, resP, () => {});
  assert.strictEqual(resP.getStatus(), 403);
  assert.strictEqual(resP.getBody().message, 'policy_deny');
  passed++;

  // 11. Policy allow-list restricts non-listed roles
  const rbacA = new RBAC();
  rbacA.addPolicy({ resource: 'ingest', action: 'write', allow: ['admin', 'superadmin'] });
  const mwA = rbacA.authorize('ingest:write');
  const reqA = mockReq({ id: 'u4', role: 'editor' });
  const resA = mockRes();
  mwA(reqA, resA, () => {});
  assert.strictEqual(resA.getStatus(), 403);
  assert.strictEqual(resA.getBody().message, 'policy_excluded');
  passed++;

  // 12. Policy allow passes for listed role
  const reqA2 = mockReq({ id: 'u5', role: 'admin' });
  const resA2 = mockRes();
  let calledA2 = false;
  mwA(reqA2, resA2, () => { calledA2 = true; });
  assert(calledA2, 'policy allow passes for listed role');
  passed++;

  // 13. Circular inheritance detection
  const circularH = [
    { role: 'a', inherits: 'b', permissions: [] },
    { role: 'b', inherits: 'a', permissions: [] },
  ];
  assert.throws(() => new RBAC(circularH), /Circular inheritance/);
  passed++;

  console.log(`All ${passed} tests passed.`);
}

run();
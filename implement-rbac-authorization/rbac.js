const DEFAULT_HIERARCHY = [
  { role: 'superadmin', inherits: 'admin', permissions: ['*'] },
  { role: 'admin', inherits: 'editor', permissions: [
    'users:delete', 'users:write', 'users:read',
    'alerts:write', 'alerts:delete',
    'ingest:write', 'ingest:delete',
    'status:write', 'status:delete',
  ]},
  { role: 'editor', inherits: 'viewer', permissions: [
    'alerts:write', 'ingest:write', 'status:write',
    'users:read',
  ]},
  { role: 'viewer', inherits: null, permissions: [
    'alerts:read', 'ingest:read', 'status:read', 'users:read',
  ]},
];

class RBAC {
  constructor(hierarchy = DEFAULT_HIERARCHY) {
    this._raw = hierarchy;
    this._resolved = new Map();
    this._policies = []; // { resource, action, allow, deny }
    this._resolveAll();
  }

  _resolveAll() {
    for (const entry of this._raw) {
      this._resolved.set(entry.role, this._resolveRole(entry.role));
    }
  }

  _resolveRole(role, seen = new Set()) {
    if (this._resolved.has(role)) return this._resolved.get(role);
    if (seen.has(role)) throw new Error(`Circular inheritance detected: ${role}`);
    seen.add(role);
    const entry = this._raw.find(e => e.role === role);
    if (!entry) throw new Error(`Unknown role: ${role}`);
    const own = new Set(entry.permissions);
    if (entry.inherits) {
      const parentPerms = this._resolveRole(entry.inherits, new Set(seen));
      for (const p of parentPerms) own.add(p);
    }
    return own;
  }

  getPermissions(role) {
    return this._resolved.get(role) || new Set();
  }

  hasPermission(role, permission) {
    const perms = this.getPermissions(role);
    if (perms.has('*')) return true;
    if (perms.has(permission)) return true;
    const [resource] = permission.split(':');
    return perms.has(`${resource}:*`);
  }

  addPolicy(policy) {
    this._policies.push(policy);
    return this;
  }

  checkPolicy(user, resource, action) {
    for (const p of this._policies) {
      if (p.resource === resource && p.action === action) {
        if (p.deny && p.deny.includes(user.role)) return { allowed: false, reason: 'policy_deny' };
        if (p.allow && !p.allow.includes(user.role)) return { allowed: false, reason: 'policy_excluded' };
      }
    }
    return { allowed: true, reason: 'policy_pass' };
  }

  authorize(requiredPermission) {
    return (req, res, next) => {
      const user = req.user || null;
      if (!user || !user.role) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
      }
      const perms = this.getPermissions(user.role);
      if (!perms && !this._resolved.has(user.role)) {
        return res.status(403).json({ error: 'Forbidden', message: `Unknown role: ${user.role}` });
      }
      if (!this.hasPermission(user.role, requiredPermission)) {
        return res.status(403).json({ error: 'Forbidden', message: `Requires ${requiredPermission}` });
      }
      const resource = requiredPermission.split(':')[0];
      const action = requiredPermission.split(':')[1];
      const policyResult = this.checkPolicy(user, resource, action);
      if (!policyResult.allowed) {
        return res.status(403).json({ error: 'Forbidden', message: policyResult.reason });
      }
      req.rbac = { role: user.role, permissions: [...perms], checked: requiredPermission };
      next();
    };
  }
}

module.exports = { RBAC, DEFAULT_HIERARCHY };
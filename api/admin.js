import { sql } from '@vercel/postgres';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

const ADMIN_ROLES = ['super_admin', 'admin'];
const SUPER_ONLY  = ['super_admin'];
const VALID_ROLES = ['super_admin', 'admin', 'manager', 'viewer'];

function hasRole(userRole, allowed) { return allowed.includes(userRole); }

async function verifyUser(username, password) {
  try {
    const { rows } = await sql`
      SELECT id, username, role, full_name, restricted_site
      FROM users
      WHERE username = ${username} AND password = ${password}
    `;
    if (!rows.length) return null;
    await sql`UPDATE users SET last_login = NOW() WHERE username = ${username}`;
    return rows[0];
  } catch { return null; }
}

async function loadForRole(role) {
  const isAdmin = hasRole(role, ADMIN_ROLES);
  const [settingsRes, sitesRes, guardsRes] = await Promise.all([
    sql`SELECT key, value FROM settings`,
    isAdmin ? sql`SELECT id, name, pin, token, created_at FROM sites ORDER BY created_at ASC` : Promise.resolve({ rows: [] }),
    isAdmin ? sql`SELECT id, name, site_id AS "siteId", badge, added_at FROM guards ORDER BY added_at ASC` : Promise.resolve({ rows: [] }),
  ]);
  const settings = {};
  settingsRes.rows.forEach(r => (settings[r.key] = r.value));
  return { sites: sitesRes.rows, guards: guardsRes.rows, settings };
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return new Response('', { status: 204, headers: CORS });
  if (req.method !== 'POST') return respond({ error: 'Method not allowed' }, 405);

  let body;
  try { body = await req.json(); }
  catch { return respond({ error: 'Invalid JSON body' }, 400); }

  const { action, username = '', password = '' } = body;

  // ── PING ──────────────────────────────────────────────────────────────────
  if (action === 'ping') {
    try { await sql`SELECT 1`; return respond({ ok: true }); }
    catch (e) { return respond({ error: 'DB unreachable: ' + e.message }, 503); }
  }

  // ── LOGIN ─────────────────────────────────────────────────────────────────
  if (action === 'login') {
    const user = await verifyUser(username, password);
    if (!user) return respond({ error: 'Invalid credentials' }, 401);
    const data = await loadForRole(user.role);
    return respond({ ok: true, user, ...data });
  }

  // ── AUTH REQUIRED ─────────────────────────────────────────────────────────
  const user = await verifyUser(username, password);
  if (!user) return respond({ error: 'Unauthorized' }, 401);

  switch (action) {

    case 'load_all': {
      const data = await loadForRole(user.role);
      return respond({ ...data, user });
    }

    // ── SITES ────────────────────────────────────────────────────────────────
    case 'save_site': {
      if (!hasRole(user.role, ADMIN_ROLES)) return respond({ error: 'Insufficient permissions' }, 403);
      const s = body.site;
      if (!s?.id || !s?.name || !s?.pin) return respond({ error: 'id, name, pin required' }, 400);
      await sql`
        INSERT INTO sites (id, name, pin, token, created_at)
        VALUES (${s.id}, ${s.name}, ${s.pin}, ${s.token||null}, ${s.created||new Date().toISOString()})
        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, pin = EXCLUDED.pin
      `;
      return respond({ ok: true });
    }

    case 'delete_site': {
      if (!hasRole(user.role, ADMIN_ROLES)) return respond({ error: 'Insufficient permissions' }, 403);
      await sql`DELETE FROM sites WHERE id = ${body.siteId}`;
      return respond({ ok: true });
    }

    // ── GUARDS ───────────────────────────────────────────────────────────────
    case 'save_guard': {
      if (!hasRole(user.role, ADMIN_ROLES)) return respond({ error: 'Insufficient permissions' }, 403);
      const g = body.guard;
      if (!g?.id || !g?.name || !g?.siteId) return respond({ error: 'id, name, siteId required' }, 400);
      await sql`
        INSERT INTO guards (id, name, site_id, badge, added_at)
        VALUES (${g.id}, ${g.name}, ${g.siteId}, ${g.badge||''}, ${g.added||new Date().toISOString()})
        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, site_id = EXCLUDED.site_id, badge = EXCLUDED.badge
      `;
      return respond({ ok: true });
    }

    case 'delete_guard': {
      if (!hasRole(user.role, ADMIN_ROLES)) return respond({ error: 'Insufficient permissions' }, 403);
      await sql`DELETE FROM guards WHERE id = ${body.guardId}`;
      return respond({ ok: true });
    }

    // ── SETTINGS ─────────────────────────────────────────────────────────────
    case 'save_setting': {
      if (!hasRole(user.role, ADMIN_ROLES)) return respond({ error: 'Insufficient permissions' }, 403);
      await sql`
        INSERT INTO settings (key, value) VALUES (${body.key}, ${body.value??''})
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
      `;
      return respond({ ok: true });
    }

    // ── OWN PASSWORD ─────────────────────────────────────────────────────────
    case 'change_own_password': {
      const { newPassword } = body;
      if (!newPassword || newPassword.length < 6) return respond({ error: 'Min 6 characters' }, 400);
      await sql`UPDATE users SET password = ${newPassword} WHERE username = ${username}`;
      return respond({ ok: true });
    }

    // ── USER MANAGEMENT (super_admin only) ────────────────────────────────────
    case 'list_users': {
      if (!hasRole(user.role, SUPER_ONLY)) return respond({ error: 'Insufficient permissions' }, 403);
      const { rows } = await sql`
        SELECT id, username, role, full_name, restricted_site, created_at, last_login
        FROM users ORDER BY created_at ASC
      `;
      return respond({ users: rows });
    }

    case 'create_user': {
      if (!hasRole(user.role, SUPER_ONLY)) return respond({ error: 'Insufficient permissions' }, 403);
      const u = body.newUser;
      if (!u?.username || !u?.password || !u?.role) return respond({ error: 'username, password, role required' }, 400);
      if (!VALID_ROLES.includes(u.role)) return respond({ error: 'Invalid role' }, 400);
      if (u.password.length < 6) return respond({ error: 'Min 6 characters' }, 400);
      const restrictedSite = u.role === 'viewer' && u.restrictedSite ? u.restrictedSite : null;
      try {
        await sql`
          INSERT INTO users (id, username, password, role, full_name, restricted_site)
          VALUES (${crypto.randomUUID()}, ${u.username}, ${u.password}, ${u.role}, ${u.fullName||''}, ${restrictedSite})
        `;
      } catch (e) {
        if (e.message?.includes('unique') || e.message?.includes('duplicate')) return respond({ error: 'Username already exists' }, 409);
        throw e;
      }
      return respond({ ok: true });
    }

    case 'update_user': {
      if (!hasRole(user.role, SUPER_ONLY)) return respond({ error: 'Insufficient permissions' }, 403);
      const { userId, updates } = body;
      if (!userId) return respond({ error: 'userId required' }, 400);
      const { rows: t } = await sql`SELECT username, role FROM users WHERE id = ${userId}`;
      if (t[0]?.username === username && updates.role && updates.role !== 'super_admin') {
        return respond({ error: 'Cannot change your own role' }, 400);
      }
      if (updates.role) await sql`UPDATE users SET role = ${updates.role} WHERE id = ${userId}`;
      if (updates.fullName !== undefined) await sql`UPDATE users SET full_name = ${updates.fullName} WHERE id = ${userId}`;
      if (updates.password) {
        if (updates.password.length < 6) return respond({ error: 'Min 6 characters' }, 400);
        await sql`UPDATE users SET password = ${updates.password} WHERE id = ${userId}`;
      }
      // Handle restricted_site — only meaningful for viewer role
      const effectiveRole = updates.role || t[0]?.role;
      if (effectiveRole === 'viewer') {
        const restrictedSite = updates.restrictedSite || null;
        await sql`UPDATE users SET restricted_site = ${restrictedSite} WHERE id = ${userId}`;
      } else {
        // Non-viewers have no site restriction
        await sql`UPDATE users SET restricted_site = NULL WHERE id = ${userId}`;
      }
      return respond({ ok: true });
    }

    case 'delete_user': {
      if (!hasRole(user.role, SUPER_ONLY)) return respond({ error: 'Insufficient permissions' }, 403);
      const { rows: s } = await sql`SELECT username FROM users WHERE id = ${body.userId}`;
      if (s[0]?.username === username) return respond({ error: 'Cannot delete your own account' }, 400);
      await sql`DELETE FROM users WHERE id = ${body.userId}`;
      return respond({ ok: true });
    }

    default:
      return respond({ error: `Unknown action: ${action}` }, 400);
  }
}

export const config = { runtime: 'edge' };

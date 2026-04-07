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

async function getCreds() {
  const { rows } = await sql`
    SELECT key, value FROM settings WHERE key IN ('adminUsername','adminPassword')
  `;
  const map = {};
  rows.forEach(r => (map[r.key] = r.value));
  return {
    username: map.adminUsername || 'admin',
    password: map.adminPassword || 'fpi2024',
  };
}

async function verifyAuth(username, password) {
  const creds = await getCreds();
  return username === creds.username && password === creds.password;
}

async function loadAll() {
  const [sitesRes, guardsRes, settingsRes] = await Promise.all([
    sql`SELECT id, name, pin, token, created_at FROM sites ORDER BY created_at ASC`,
    sql`SELECT id, name, site_id AS "siteId", badge, added_at FROM guards ORDER BY added_at ASC`,
    sql`SELECT key, value FROM settings`,
  ]);
  const settings = {};
  settingsRes.rows.forEach(r => (settings[r.key] = r.value));
  return {
    sites: sitesRes.rows,
    guards: guardsRes.rows,
    settings,
  };
}

export default async function handler(req) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('', { status: 204, headers: CORS });
  }
  if (req.method !== 'POST') {
    return respond({ error: 'Method not allowed' }, 405);
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return respond({ error: 'Invalid JSON body' }, 400);
  }

  const { action, username = 'admin', password = '' } = body;

  // ── LOGIN ──────────────────────────────────────────────────────────
  if (action === 'login') {
    const ok = await verifyAuth(username, password);
    if (!ok) return respond({ error: 'Invalid credentials' }, 401);
    const data = await loadAll();
    return respond({ ok: true, ...data });
  }

  // ── ALL OTHER ACTIONS REQUIRE AUTH ─────────────────────────────────
  const authed = await verifyAuth(username, password);
  if (!authed) return respond({ error: 'Unauthorized' }, 401);

  switch (action) {

    // ── LOAD ALL ──────────────────────────────────────────────────────
    case 'load_all': {
      const data = await loadAll();
      return respond(data);
    }

    // ── SAVE SITE (upsert) ────────────────────────────────────────────
    case 'save_site': {
      const s = body.site;
      if (!s?.id || !s?.name || !s?.pin) {
        return respond({ error: 'id, name, and pin are required' }, 400);
      }
      await sql`
        INSERT INTO sites (id, name, pin, token, created_at)
        VALUES (
          ${s.id},
          ${s.name},
          ${s.pin},
          ${s.token || null},
          ${s.created || new Date().toISOString()}
        )
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          pin  = EXCLUDED.pin
      `;
      return respond({ ok: true });
    }

    // ── DELETE SITE ───────────────────────────────────────────────────
    case 'delete_site': {
      if (!body.siteId) return respond({ error: 'siteId required' }, 400);
      // Guards are deleted via CASCADE on the FK
      await sql`DELETE FROM sites WHERE id = ${body.siteId}`;
      return respond({ ok: true });
    }

    // ── SAVE GUARD (upsert) ───────────────────────────────────────────
    case 'save_guard': {
      const g = body.guard;
      if (!g?.id || !g?.name || !g?.siteId) {
        return respond({ error: 'id, name, and siteId are required' }, 400);
      }
      await sql`
        INSERT INTO guards (id, name, site_id, badge, added_at)
        VALUES (
          ${g.id},
          ${g.name},
          ${g.siteId},
          ${g.badge || ''},
          ${g.added || new Date().toISOString()}
        )
        ON CONFLICT (id) DO UPDATE SET
          name    = EXCLUDED.name,
          site_id = EXCLUDED.site_id,
          badge   = EXCLUDED.badge
      `;
      return respond({ ok: true });
    }

    // ── DELETE GUARD ──────────────────────────────────────────────────
    case 'delete_guard': {
      if (!body.guardId) return respond({ error: 'guardId required' }, 400);
      await sql`DELETE FROM guards WHERE id = ${body.guardId}`;
      return respond({ ok: true });
    }

    // ── SAVE SETTING ──────────────────────────────────────────────────
    case 'save_setting': {
      if (!body.key) return respond({ error: 'key required' }, 400);
      await sql`
        INSERT INTO settings (key, value)
        VALUES (${body.key}, ${body.value ?? ''})
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
      `;
      return respond({ ok: true });
    }

    default:
      return respond({ error: `Unknown action: ${action}` }, 400);
  }
}

export const config = { runtime: 'edge' };

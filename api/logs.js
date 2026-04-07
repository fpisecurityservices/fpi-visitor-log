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

async function verifyUser(username, password) {
  try {
    const { rows } = await sql`
      SELECT role, restricted_site FROM users
      WHERE username = ${username} AND password = ${password}
    `;
    return rows.length ? rows[0] : null;
  } catch { return null; }
}

export default async function handler(req) {
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

  const { action } = body;

  // ── APPEND LOG (guard form — no auth required) ─────────────────────
  // The site PIN was already verified client-side before the guard
  // could access the form. We trust the submission at this point.
  if (action === 'append_log') {
    const {
      date, time_in, full_name, visitor_type,
      company_unit, id_verified, site_id, timestamp_iso
    } = body;

    if (!full_name || !site_id) {
      return respond({ error: 'full_name and site_id are required' }, 400);
    }

    await sql`
      INSERT INTO logs
        (date, time_in, full_name, visitor_type, company_unit,
         id_verified, site_id, timestamp_iso)
      VALUES (
        ${date || new Date().toLocaleDateString('en-US')},
        ${time_in || ''},
        ${full_name},
        ${visitor_type || ''},
        ${company_unit || ''},
        ${id_verified || 'No'},
        ${site_id},
        ${timestamp_iso ? new Date(timestamp_iso) : new Date()}
      )
    `;
    return respond({ ok: true });
  }

  // ── GET LOGS (reports — auth required) ────────────────────────────
  if (action === 'get_logs') {
    const { username = 'admin', password = '' } = body;
    const authUser = await verifyUser(username, password);
    if (!authUser) return respond({ error: 'Unauthorized' }, 401);

    const { from, to, type } = body;
    // Server-side enforcement: viewer with restricted_site overrides any siteId sent by client
    const siteId = authUser.restricted_site || body.siteId || null;

    // Build dynamic query with optional filters
    // We use parameterized queries for safety
    let logs;

    // Use created_at (TIMESTAMPTZ) for reliable date range filtering
    const fromTs = from ? from + 'T00:00:00Z' : '2000-01-01T00:00:00Z';
    const toTs   = to   ? to   + 'T23:59:59Z' : '2099-12-31T23:59:59Z';

    if (siteId && type) {
      logs = await sql`
        SELECT date, time_in, full_name, visitor_type, company_unit,
               id_verified, site_id, timestamp_iso
        FROM logs
        WHERE created_at >= ${fromTs}::timestamptz
          AND created_at <= ${toTs}::timestamptz
          AND site_id = ${siteId}
          AND visitor_type = ${type}
        ORDER BY created_at DESC
        LIMIT 5000
      `;
    } else if (siteId) {
      logs = await sql`
        SELECT date, time_in, full_name, visitor_type, company_unit,
               id_verified, site_id, timestamp_iso
        FROM logs
        WHERE created_at >= ${fromTs}::timestamptz
          AND created_at <= ${toTs}::timestamptz
          AND site_id = ${siteId}
        ORDER BY created_at DESC
        LIMIT 5000
      `;
    } else if (type) {
      logs = await sql`
        SELECT date, time_in, full_name, visitor_type, company_unit,
               id_verified, site_id, timestamp_iso
        FROM logs
        WHERE created_at >= ${fromTs}::timestamptz
          AND created_at <= ${toTs}::timestamptz
          AND visitor_type = ${type}
        ORDER BY created_at DESC
        LIMIT 5000
      `;
    } else {
      logs = await sql`
        SELECT date, time_in, full_name, visitor_type, company_unit,
               id_verified, site_id, timestamp_iso
        FROM logs
        WHERE created_at >= ${fromTs}::timestamptz
          AND created_at <= ${toTs}::timestamptz
        ORDER BY created_at DESC
        LIMIT 5000
      `;
    }

    return respond({ logs: logs.rows, total: logs.rows.length });
  }

  // ── DAILY SUMMARY (for scheduled email reports) ───────────────────
  if (action === 'daily_summary') {
    const { username = 'admin', password = '', date } = body;
    const authUser = await verifyUser(username, password);
    if (!authUser) return respond({ error: 'Unauthorized' }, 401);

    const targetDate = date || new Date().toLocaleDateString('en-US');
    const summaryFrom = targetDate + 'T00:00:00Z';
    const summaryTo   = targetDate + 'T23:59:59Z';
    const { rows } = await sql`
      SELECT date, time_in, full_name, visitor_type, company_unit,
             id_verified, site_id
      FROM logs
      WHERE created_at >= ${summaryFrom}::timestamptz
        AND created_at <= ${summaryTo}::timestamptz
      ORDER BY created_at ASC
    `;
    return respond({ logs: rows, date: targetDate, total: rows.length });
  }

  return respond({ error: `Unknown action: ${action}` }, 400);
}

export const config = { runtime: 'edge' };

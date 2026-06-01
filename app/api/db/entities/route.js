/**
 * /api/db/entities
 *   GET  → all entities (server-side SQLite)
 *   POST → upsert one or many entities
 */

import { NextResponse }              from 'next/server';
import { getDB, upsertEntity, batchUpsertEntities } from '../../../../lib/db.js';
import { requireSecret }             from '../../../../lib/auth.js';

export async function GET(request) {
  const authErr = requireSecret(request, true); // server-only secret
  if (authErr) return authErr;
  try {
    const db = getDB();
    if (!db) return NextResponse.json({ ok: false, error: 'DB unavailable' }, { status: 503 });
    const { searchParams } = new URL(request.url);
    const limit   = Math.min(parseInt(searchParams.get('limit')  || '500', 10), 2000);
    const type    = searchParams.get('type')   || null;
    const search  = searchParams.get('search') || null;

    let sql    = 'SELECT * FROM entities';
    const args = [];
    const where = [];

    if (type)   { where.push('entity_type = ?');    args.push(type); }
    if (search) { where.push('(name LIKE ? OR farm_name LIKE ? OR vessel_name LIKE ?)');
                  const p = `%${search}%`;
                  args.push(p, p, p); }

    if (where.length) sql += ' WHERE ' + where.join(' AND ');
    sql += ' ORDER BY COALESCE(saved_at, created_at) DESC LIMIT ?';
    args.push(limit);

    const rows = db.prepare(sql).all(...args);
    return NextResponse.json({ ok: true, data: rows, count: rows.length });
  } catch (e) {
    console.error('[/api/db/entities GET]', e);
    return NextResponse.json({ ok: false, error: e.message }, { status: 500 });
  }
}

export async function POST(request) {
  const authErr = requireSecret(request, true);
  if (authErr) return authErr;
  try {
    if (!getDB()) return NextResponse.json({ ok: false, error: 'DB unavailable' }, { status: 503 });
    const body = await request.json();
    // Accept a single record or an array
    const records = Array.isArray(body) ? body : [body];
    const count   = batchUpsertEntities(records);
    return NextResponse.json({ ok: true, count });
  } catch (e) {
    console.error('[/api/db/entities POST]', e);
    return NextResponse.json({ ok: false, error: e.message }, { status: 500 });
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

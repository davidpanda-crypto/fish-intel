/**
 * /api/db/entities/[id]
 *   DELETE → remove entity by local_id
 *   PATCH  → update specific fields (e.g. notes, verified)
 */

import { NextResponse } from 'next/server';
import { getDB }        from '../../../../../lib/db.js';

export async function DELETE(request, { params }) {
  try {
    const { id } = await params;
    const db     = getDB();
    db.prepare('DELETE FROM entities WHERE local_id = ?').run(id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return NextResponse.json({ ok: false, error: e.message }, { status: 500 });
  }
}

export async function PATCH(request, { params }) {
  try {
    const { id }  = await params;
    const patch   = await request.json();
    const db      = getDB();
    const allowed = ['notes', 'verified', 'description', 'certification', 'species', 'directus_id'];
    const sets    = [];
    const args    = [];

    for (const [k, v] of Object.entries(patch)) {
      if (allowed.includes(k)) { sets.push(`${k} = ?`); args.push(v); }
    }
    if (!sets.length) return NextResponse.json({ ok: false, error: 'No patchable fields' }, { status: 400 });

    sets.push("updated_at = datetime('now')");
    args.push(id);
    db.prepare(`UPDATE entities SET ${sets.join(', ')} WHERE local_id = ?`).run(...args);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return NextResponse.json({ ok: false, error: e.message }, { status: 500 });
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

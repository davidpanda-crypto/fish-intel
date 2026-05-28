/**
 * /api/directus/[...path] — Directus proxy
 * Forwards any request to Directus with the server-side token.
 * The token in DIRECTUS_TOKEN never reaches the browser.
 *
 * Examples:
 *   GET  /api/directus/items/fish_entities
 *   POST /api/directus/items/fish_entities
 *   PATCH /api/directus/items/fish_entities/123
 */

import { NextResponse } from 'next/server';

const DIRECTUS_URL   = process.env.DIRECTUS_URL?.replace(/\/$/, '');
const DIRECTUS_TOKEN = process.env.DIRECTUS_TOKEN;

async function proxy(request, { params }) {
  if (!DIRECTUS_URL || !DIRECTUS_TOKEN) {
    return NextResponse.json(
      { error: 'Directus not configured — set DIRECTUS_URL and DIRECTUS_TOKEN in .env.local' },
      { status: 503 }
    );
  }

  const { path } = await params;
  const subPath  = Array.isArray(path) ? path.join('/') : path;
  const search   = new URL(request.url).search;
  const target   = `${DIRECTUS_URL}/${subPath}${search}`;

  let bodyText;
  if (['POST', 'PATCH', 'PUT'].includes(request.method)) {
    bodyText = await request.text();
  }

  const res = await fetch(target, {
    method:  request.method,
    headers: {
      'Authorization': `Bearer ${DIRECTUS_TOKEN}`,
      'Content-Type':  'application/json',
    },
    body: bodyText || undefined,
  });

  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.status });
}

export const GET    = proxy;
export const POST   = proxy;
export const PATCH  = proxy;
export const DELETE = proxy;

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

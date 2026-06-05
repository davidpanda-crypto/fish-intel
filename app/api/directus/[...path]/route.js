/**
 * /api/directus/[...path] — Directus proxy
 *
 * Forwards requests to Directus using the server-side DIRECTUS_TOKEN env var.
 * The token NEVER reaches the browser — clients authenticate with
 * x-api-secret (NEXT_PUBLIC_API_SECRET) which is safe to bake into the bundle.
 *
 * Allowed paths (prevents enumeration of admin endpoints):
 *   items   — collection CRUD
 *   files   — file metadata
 *   assets  — file downloads
 *
 * Examples:
 *   GET   /api/directus/items/fish_entities
 *   POST  /api/directus/items/fish_entities
 *   PATCH /api/directus/items/fish_entities/123
 */

import { NextResponse } from 'next/server';
import { requireSecret } from '../../../../lib/auth.js';

const DIRECTUS_URL   = process.env.DIRECTUS_URL?.replace(/\/$/, '');
const DIRECTUS_TOKEN = process.env.DIRECTUS_TOKEN;

// Only these top-level Directus paths may be proxied
const ALLOWED_PATHS = ['items', 'files', 'assets'];

async function proxy(request, { params }) {
  // serverOnly=false: accepts NEXT_PUBLIC_API_SECRET from browser clients.
  // The Directus token itself is still protected — it never leaves the server.
  const authErr = requireSecret(request, false);
  if (authErr) return authErr;

  if (!DIRECTUS_URL || !DIRECTUS_TOKEN) {
    return NextResponse.json(
      { error: 'Directus not configured — set DIRECTUS_URL and DIRECTUS_TOKEN in .env.local' },
      { status: 503 }
    );
  }

  const { path } = await params;
  const segments = Array.isArray(path) ? path : [path];

  // Enforce allowlist on the first path segment
  if (!ALLOWED_PATHS.includes(segments[0])) {
    return NextResponse.json({ error: 'Path not allowed' }, { status: 403 });
  }

  const subPath  = segments.join('/');
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

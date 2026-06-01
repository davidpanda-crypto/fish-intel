/**
 * Shared API authentication helper.
 *
 * Routes that are called from the browser (ai, scrape, health) check
 * x-api-secret against NEXT_PUBLIC_API_SECRET (baked into the JS bundle —
 * stops automated scanners but not a determined attacker who inspects the JS).
 *
 * Routes that are never called from the browser (db/*) check against
 * API_SECRET (server-only env var — truly secret).
 *
 * Set both to the same value in .env.local / Vercel env vars.
 * Leave unset in development to skip the check entirely.
 */

import { timingSafeEqual, createHash } from 'crypto';

/**
 * Constant-time string comparison — prevents timing attacks where an attacker
 * measures response latency to guess the secret one byte at a time.
 */
function safeCompare(a, b) {
  try {
    // Hash both values to a fixed length so timingSafeEqual works regardless
    // of input length (it requires equal-length Buffers).
    const ha = createHash('sha256').update(a).digest();
    const hb = createHash('sha256').update(b).digest();
    return timingSafeEqual(ha, hb);
  } catch {
    return false;
  }
}

export function requireSecret(request, serverOnly = false) {
  const secret = serverOnly
    ? process.env.API_SECRET
    : (process.env.API_SECRET || process.env.NEXT_PUBLIC_API_SECRET);

  // No secret configured → open in dev, enforced in prod
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      return new Response(JSON.stringify({ error: 'API not configured' }), {
        status: 503, headers: { 'content-type': 'application/json' },
      });
    }
    return null; // dev: skip check
  }

  const provided = request.headers.get('x-api-secret') || '';
  if (!safeCompare(provided, secret)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401, headers: { 'content-type': 'application/json' },
    });
  }
  return null; // ok
}

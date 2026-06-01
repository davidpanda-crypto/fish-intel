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

  const provided = request.headers.get('x-api-secret');
  if (provided !== secret) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401, headers: { 'content-type': 'application/json' },
    });
  }
  return null; // ok
}

/**
 * /api/scrape — server-side URL fetching
 * Replaces the CORS proxy chain. The server can fetch any URL directly,
 * with realistic browser headers and no CORS restrictions.
 */

import { NextResponse } from 'next/server';

const USER_AGENTS = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
];

const REFERERS = [
  'https://www.google.com/search?q=fish+farm+aquaculture',
  'https://www.bing.com/search?q=seafood+vessel+registry',
  'https://duckduckgo.com/?q=fish+mill+processing',
];

function validateUrl(url) {
  try {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const h = u.hostname;
    // Block private/local addresses
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)/.test(h)) return false;
    return true;
  } catch { return false; }
}

export async function POST(request) {
  let url;
  try { ({ url } = await request.json()); }
  catch { return NextResponse.json({ ok: false, error: 'Invalid JSON' }, { status: 400 }); }

  if (!url || !validateUrl(url)) {
    return NextResponse.json({ ok: false, error: 'Invalid or blocked URL' }, { status: 400 });
  }

  const ua  = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
  const ref = REFERERS[Math.floor(Math.random() * REFERERS.length)];

  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), 20000);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent':      ua,
        'Referer':         ref,
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control':   'no-cache',
        'Pragma':          'no-cache',
        'DNT':             '1',
      },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return NextResponse.json({ ok: false, error: `HTTP ${res.status}`, status: res.status });
    }

    const text = await res.text();
    if (text.length < 50) {
      return NextResponse.json({ ok: false, error: 'Empty response' });
    }

    // Detect block pages
    const lc = text.toLowerCase();
    const blocked = ['access denied','403 forbidden','just a moment','enable javascript',
      'are you human','cloudflare ray id','cf-ray'].some(kw => lc.includes(kw) && text.length < 10000);
    if (blocked) {
      return NextResponse.json({ ok: false, error: 'Block page detected', blocked: true });
    }

    return NextResponse.json({ ok: true, text, finalUrl: res.url });

  } catch (e) {
    clearTimeout(timeout);
    return NextResponse.json({ ok: false, error: e.message });
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

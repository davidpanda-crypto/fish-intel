/**
 * /api/scrape — server-side URL fetching
 * Replaces the CORS proxy chain. The server can fetch any URL directly,
 * with realistic browser headers and no CORS restrictions.
 */

import { NextResponse } from 'next/server';
import { requireSecret } from '../../../lib/auth.js';

// Vercel: Hobby = 10 s hard cap (will warn), Pro = up to 60 s.
// Set to 60 so the route works properly on Pro / self-hosted.
export const maxDuration = 60;

// Chrome 150 on Windows/Mac/Linux — most common desktop UA worldwide (2025-2026)
const BROWSER_PROFILES = [
  {
    ua:  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
    ch:  '"Chromium";v="150", "Google Chrome";v="150", "Not-A.Brand";v="99"',
    plat: '"Windows"',
  },
  {
    ua:  'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
    ch:  '"Chromium";v="150", "Google Chrome";v="150", "Not-A.Brand";v="99"',
    plat: '"macOS"',
  },
  {
    ua:  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
    ch:  '"Chromium";v="150", "Google Chrome";v="150", "Not-A.Brand";v="99"',
    plat: '"Linux"',
  },
  {
    ua:  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    ch:  null,  // Firefox does not send sec-ch-ua
    plat: null,
  },
  {
    ua:  'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    ch:  null,  // Safari does not send sec-ch-ua
    plat: null,
  },
];

// Realistic referrers — rotated to look like organic traffic
const REFERERS = [
  'https://www.google.com/',
  'https://www.bing.com/',
  'https://duckduckgo.com/',
  'https://www.google.co.uk/',
  'https://www.google.no/',
  'https://www.google.cn/',
  'https://www.baidu.com/',
];

// Accept-Language strings covering the main languages for the target sites
const ACCEPT_LANGS = [
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9',
  'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
  'zh-CN,zh;q=0.9,en;q=0.8',
  'en-US,en;q=0.9,no;q=0.8,nb;q=0.7',
];

function validateUrl(url) {
  try {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const h = u.hostname;
    // Block RFC-1918 private ranges and loopback
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)/.test(h)) return false;
    // Block cloud instance metadata endpoints (SSRF)
    if (/^169\.254\./.test(h)) return false;               // AWS/Azure link-local metadata
    if (/metadata\.google\.internal$/i.test(h)) return false; // GCP metadata
    if (/^fd[0-9a-f]{2}:/i.test(h)) return false;          // IPv6 ULA
    if (/^fe[89ab][0-9a-f]:/i.test(h)) return false;       // IPv6 link-local
    return true;
  } catch { return false; }
}

export async function POST(request) {
  const authErr = requireSecret(request);
  if (authErr) return authErr;

  let url;
  try { ({ url } = await request.json()); }
  catch { return NextResponse.json({ ok: false, error: 'Invalid JSON' }, { status: 400 }); }

  if (!url || !validateUrl(url)) {
    return NextResponse.json({ ok: false, error: 'Invalid or blocked URL' }, { status: 400 });
  }

  const profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
  const ref     = REFERERS[Math.floor(Math.random() * REFERERS.length)];
  const lang    = ACCEPT_LANGS[Math.floor(Math.random() * ACCEPT_LANGS.length)];

  // Chinese sites need a longer timeout — government portals can be slow
  const isCN = /\.(cn|com\.cn|gov\.cn|weixin\.qq\.com|sogou\.com)/.test(new URL(url).hostname);
  const timeoutMs = isCN ? 28000 : 20000;

  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), timeoutMs);

  // Build headers — only add sec-ch-ua for Chrome profiles (Firefox/Safari don't send it)
  const headers = {
    'User-Agent':      profile.ua,
    'Referer':         ref,
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': lang,
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Cache-Control':   'no-cache',
    'Pragma':          'no-cache',
    'DNT':             '1',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest':  'document',
    'Sec-Fetch-Mode':  'navigate',
    'Sec-Fetch-Site':  'cross-site',
    'Sec-Fetch-User':  '?1',
  };
  if (profile.ch)   headers['sec-ch-ua']          = profile.ch;
  if (profile.plat) headers['sec-ch-ua-platform']  = profile.plat;
  if (profile.ch)   headers['sec-ch-ua-mobile']    = '?0';

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return NextResponse.json({ ok: false, error: `HTTP ${res.status}`, status: res.status });
    }

    const text = await res.text();
    if (text.length < 50) {
      return NextResponse.json({ ok: false, error: 'Empty response' });
    }

    // Detect block / CAPTCHA pages
    const lc = text.toLowerCase();
    const BLOCK_SIGNALS = [
      'access denied','403 forbidden','just a moment','enable javascript',
      'are you human','cloudflare ray id','cf-ray','ddos protection',
      'security check','please verify','bot detection','verifying you are human',
    ];
    const blocked = BLOCK_SIGNALS.some(kw => lc.includes(kw) && text.length < 12000);
    if (blocked) {
      return NextResponse.json({ ok: false, error: 'Block page detected', blocked: true });
    }

    // Return content type alongside text so the client can handle non-HTML responses
    const contentType = res.headers.get('content-type') || '';
    return NextResponse.json({ ok: true, text, finalUrl: res.url, contentType });

  } catch (e) {
    clearTimeout(timeout);
    return NextResponse.json({ ok: false, error: e.message });
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

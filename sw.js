/**
 * Fish Farm & Ship Intelligence — Service Worker
 * Strategy: Cache-first for app shell, network-first for API calls.
 *
 * Works correctly on any base path (localhost, GitHub Pages /fish-intel/, etc.)
 * by computing BASE dynamically from the SW's own URL.
 */
const CACHE_VER = 'fish-intel-v12';

// Derive base path from the SW's location (e.g. /fish-intel/ or /)
const BASE = self.location.pathname.replace(/\/sw\.js$/, '/');

const SHELL_URLS = [
  BASE,
  BASE + 'index.html',
  BASE + 'css/style.css',
  BASE + 'js/app.js',
  BASE + 'js/modules/idb.js',
  BASE + 'js/modules/router.js',
  BASE + 'js/modules/cache.js',
];

// ── Install: pre-cache app shell ──────────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_VER)
      .then(c => c.addAll(SHELL_URLS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: evict old caches ────────────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_VER).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch strategy ────────────────────────────────────────────────────────────
// HTML → network-first  (always get fresh markup; fall back to cache offline)
// JS/CSS/fonts → cache-first with background revalidation (fast paint)
// External/API → pass-through (never intercept)
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = new URL(e.request.url);

  // Never intercept cross-origin requests (API proxies, CDNs, Anthropic API)
  if (url.origin !== self.location.origin) return;

  const isHTML = e.request.headers.get('accept')?.includes('text/html') ||
                 url.pathname.endsWith('.html') ||
                 url.pathname === BASE ||
                 url.pathname === BASE.slice(0, -1); // trailing-slash variant

  if (isHTML) {
    // Network-first: always try to get fresh HTML; cache as offline fallback
    e.respondWith(
      fetch(e.request)
        .then(res => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE_VER).then(c => c.put(e.request, clone));
          }
          return res;
        })
        .catch(async () => {
          const cached = await caches.match(e.request);
          return cached || new Response('Offline — open the app when connected.', {
            status: 503, headers: { 'Content-Type': 'text/plain' },
          });
        })
    );
  } else {
    // Cache-first + background revalidation for JS, CSS, fonts
    e.respondWith(
      caches.open(CACHE_VER).then(async cache => {
        const cached = await cache.match(e.request);
        const revalidate = fetch(e.request).then(res => {
          if (res.ok) cache.put(e.request, res.clone());
          return res;
        }).catch(() => cached);

        return cached || revalidate;
      })
    );
  }
});

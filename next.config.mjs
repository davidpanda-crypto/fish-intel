/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Allow better-sqlite3 native bindings
  serverExternalPackages: ['better-sqlite3'],

  // Content Security Policy + CORS headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self' 'unsafe-inline' https: data: blob:",
              "img-src * data: blob:",
              "connect-src *",
              "worker-src 'self' blob:",
            ].join('; '),
          },
          { key: 'X-Content-Type-Options',  value: 'nosniff' },
          { key: 'Referrer-Policy',         value: 'no-referrer' },
          { key: 'X-Frame-Options',         value: 'SAMEORIGIN' },
          { key: 'Permissions-Policy',      value: 'camera=(), microphone=(), geolocation=(self)' },
        ],
      },
      {
        // CORS for API routes — restrict to same origin in production.
        // x-api-secret must be listed here or browser preflight will block it.
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin',  value: process.env.NEXT_PUBLIC_APP_URL || '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, DELETE, PATCH, OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization, x-api-secret' },
        ],
      },
    ];
  },
};

export default nextConfig;

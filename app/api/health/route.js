// Simple ping — app.js checks this to detect Next.js mode and provider availability
export async function GET() {
  return Response.json({
    ok: true,
    providers: {
      claude:   !!process.env.ANTHROPIC_API_KEY,
      qwen:     !!process.env.QWEN_ENDPOINT,
      directus: !!(process.env.DIRECTUS_URL && process.env.DIRECTUS_TOKEN),
    },
  });
}

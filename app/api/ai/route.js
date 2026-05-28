/**
 * /api/ai — unified AI proxy
 * Routes to Qwen32B (DGX Spark / Ollama) or Claude (Anthropic).
 * API keys stay on the server — never sent to the browser.
 *
 * Priority: Qwen (if QWEN_ENDPOINT set) → Claude (if ANTHROPIC_API_KEY set)
 * The client can override by passing { provider: 'claude' } or { provider: 'qwen' }.
 */

import { NextResponse } from 'next/server';

// Vercel: Hobby = 10 s hard cap (will warn), Pro = up to 60 s.
export const maxDuration = 60;

export async function POST(request) {
  let body;
  try { body = await request.json(); }
  catch { return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { system = '', user = '', maxTokens = 800, provider = 'auto' } = body;

  const hasQwen   = !!process.env.QWEN_ENDPOINT;
  const hasClaude = !!process.env.ANTHROPIC_API_KEY;

  // Determine which provider to use
  const useQwen = (provider === 'qwen' || (provider === 'auto' && hasQwen));
  const useClaude = !useQwen && (provider === 'claude' || (provider === 'auto' && hasClaude));

  // ── Qwen32B via OpenAI-compatible endpoint ────────────────────────────────
  if (useQwen && hasQwen) {
    const endpoint = process.env.QWEN_ENDPOINT.replace(/\/$/, '') + '/v1/chat/completions';
    const model    = process.env.QWEN_MODEL || 'qwen2.5:32b';

    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 60000);

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          temperature: 0.2,
          messages: [
            { role: 'system', content: system },
            { role: 'user',   content: user   },
          ],
        }),
      });
      clearTimeout(timeout);

      if (!res.ok) {
        const err = await res.text();
        return NextResponse.json({ error: `Qwen ${res.status}: ${err.slice(0, 200)}` }, { status: 502 });
      }

      const data = await res.json();
      const text = data.choices?.[0]?.message?.content || '';
      return NextResponse.json({ text, provider: 'qwen', model });

    } catch (e) {
      clearTimeout(timeout);
      // If Qwen is unreachable, fall through to Claude if available
      if (!hasClaude) {
        return NextResponse.json({ error: `Qwen unreachable: ${e.message}` }, { status: 503 });
      }
      // fall through
    }
  }

  // ── Claude via Anthropic API ──────────────────────────────────────────────
  if (useClaude && hasClaude) {
    const model = process.env.CLAUDE_MODEL || 'claude-3-5-haiku-20241022';

    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 60000);

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'x-api-key':          process.env.ANTHROPIC_API_KEY,
          'anthropic-version':  '2023-06-01',
          'content-type':       'application/json',
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          system,
          messages: [{ role: 'user', content: user }],
        }),
      });
      clearTimeout(timeout);

      if (!res.ok) {
        const err = await res.text();
        return NextResponse.json({ error: `Claude ${res.status}: ${err.slice(0, 200)}` }, { status: 502 });
      }

      const data = await res.json();
      const text = data.content?.[0]?.text || '';
      return NextResponse.json({ text, provider: 'claude', model });

    } catch (e) {
      clearTimeout(timeout);
      return NextResponse.json({ error: `Claude unreachable: ${e.message}` }, { status: 503 });
    }
  }

  return NextResponse.json(
    { error: 'No AI provider configured. Set ANTHROPIC_API_KEY or QWEN_ENDPOINT in .env.local' },
    { status: 503 }
  );
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}

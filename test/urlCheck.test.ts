import { describe, expect, it } from 'vitest';
import { diagnoseUrl, normalizeUrl } from '../src/core/urlCheck.js';
import { fakeCtx, fixture } from './helpers.js';

describe('normalizeUrl', () => {
  it('adds https:// and rejects unsupported schemes', () => {
    expect(normalizeUrl('chatgpt.com')?.toString()).toBe('https://chatgpt.com/');
    expect(normalizeUrl('wss://example.com/ws')?.protocol).toBe('wss:');
    expect(normalizeUrl('ftp://example.com')).toBeNull();
    expect(normalizeUrl('http://')).toBeNull();
  });
});

describe('diagnoseUrl', () => {
  it('reports a Netfree block with reason and Hebrew explanation', async () => {
    const d = await diagnoseUrl(
      fakeCtx({ http: () => ({ ok: true, status: 418, statusText: 'Blocked by NetFree', body: fixture('block-unknown.html') }) }),
      'https://www.reddit.com',
    );
    expect(d.status).toBe('fail');
    expect(d.block?.reason).toBe('unknown');
    expect(d.block?.explanation.known).toBe(true);
    expect(d.summaryHe).toContain('חסומה');
    expect(d.steps.map((s) => s.id)).toEqual(['dns', 'tcp', 'tls', 'http']);
  });

  it('surfaces injected notes as a warning with wiki links', async () => {
    const d = await diagnoseUrl(fakeCtx({ http: () => ({ ok: true, status: 200, body: fixture('chatgpt-note.html') }) }), 'https://chatgpt.com');
    expect(d.status).toBe('warn');
    expect(d.injection?.notes[0]?.links.some((l) => l.url === 'https://netfree.link/wiki/AI_Chats_in_NetFree')).toBe(true);
    expect(d.steps.find((s) => s.id === 'notes')?.status).toBe('warn');
  });

  it('stops at DNS failure', async () => {
    const d = await diagnoseUrl(fakeCtx({ dns: () => ({ addresses: [], error: 'ENOTFOUND' }) }), 'https://nope.invalid');
    expect(d.status).toBe('fail');
    expect(d.steps).toHaveLength(1);
  });

  it('warns (not fails) when Node does not trust a Netfree certificate', async () => {
    const ctx = fakeCtx();
    const orig = ctx.tlsProbe.bind(ctx);
    ctx.tlsProbe = async (h, p) => ({ ...(await orig(h, p)), authorized: false, authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN' });
    const d = await diagnoseUrl(ctx, 'https://www.google.com');
    expect(d.steps.find((s) => s.id === 'tls')?.status).toBe('warn');
  });

  it('tests WebSocket upgrades for wss:// URLs', async () => {
    const d = await diagnoseUrl(fakeCtx({ http: () => ({ ok: true, status: 404, body: '' }) }), 'wss://echo.example.com/ws');
    expect(d.steps.map((s) => s.id)).toEqual(['dns', 'tcp', 'tls', 'http', 'websocket']);
    expect(d.steps.find((s) => s.id === 'websocket')?.status).toBe('ok');
  });

  it('detects a blocked WebSocket handshake', async () => {
    const body = `<iframe src="//netfree.link/block/#${encodeURIComponent(JSON.stringify({ block: 'risk-type', page_info: { url: 'wss://x/ws' } }))}"></iframe>`;
    const d = await diagnoseUrl(
      fakeCtx({ http: () => ({ ok: true, status: 200, body: '' }), ws: () => ({ ok: true, upgraded: false, status: 418, body }) }),
      'wss://x.example.com/ws',
    );
    expect(d.status).toBe('fail');
    expect(d.block?.reason).toBe('risk-type');
  });
});

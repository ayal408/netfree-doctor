import { execFile } from 'node:child_process';
import { X509Certificate, randomBytes } from 'node:crypto';
import { promises as dnsp } from 'node:dns';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import type { CertInfo, Ctx, ExecResult, HttpResult, OfficialCert, TlsProbeResult, WsResult } from '../core/types.js';
import { acceptDownloadedCert, NETFREE_CERT_BASE, NETFREE_CERT_FILES, normalizeThumbprint, officialCertFromPem } from '../core/parsers/certs.js';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 netfree-doctor';
const MAX_BODY = 512 * 1024;

export function defaultDataDir(): string {
  return path.join(os.homedir(), '.netfree-doctor');
}

export function execCmd(file: string, args: string[], timeoutMs = 30000): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 16 * 1024 * 1024, encoding: 'utf8', env: process.env },
      (err, stdout, stderr) => {
        if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
          resolve({ code: -1, stdout: '', stderr: '', error: `${file}: not found` });
          return;
        }
        const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? ((err as { code: number }).code) : 1) : 0;
        const res: ExecResult = { code, stdout: String(stdout), stderr: String(stderr) };
        if (err && (err as { killed?: boolean }).killed) res.error = `${file}: timed out`;
        resolve(res);
      },
    );
  });
}

function toPem(raw: Buffer): string | undefined {
  try {
    return new X509Certificate(raw).toString();
  } catch {
    return undefined;
  }
}

function certInfo(c: tls.DetailedPeerCertificate): CertInfo {
  const flat = (o: unknown): Record<string, string> => {
    const out: Record<string, string> = {};
    if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) out[k] = Array.isArray(v) ? v.join(', ') : String(v);
    return out;
  };
  const pem = c.raw ? toPem(c.raw) : undefined;
  return {
    subject: flat(c.subject),
    issuer: flat(c.issuer),
    sha1: normalizeThumbprint(c.fingerprint ?? ''),
    sha256: normalizeThumbprint(c.fingerprint256 ?? ''),
    validTo: c.valid_to,
    ...(pem ? { pem } : {}),
  };
}

function errMsg(e: unknown): string {
  if (e && typeof e === 'object' && 'code' in e && typeof (e as { code: unknown }).code === 'string') {
    return `${(e as { code: string }).code}: ${(e as unknown as Error).message}`;
  }
  return e instanceof Error ? e.message : String(e);
}

function tlsProbeRaw(host: string, port: number, timeoutMs: number): Promise<TlsProbeResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;
    const finish = (r: TlsProbeResult) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    // rejectUnauthorized:false so we can *inspect* the chain; trust is reported via `authorized`.
    const socket = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false }, () => {
      const chain: CertInfo[] = [];
      let c: tls.DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
      const seen = new Set<string>();
      while (c && c.fingerprint256 && !seen.has(c.fingerprint256)) {
        seen.add(c.fingerprint256);
        chain.push(certInfo(c));
        c = c.issuerCertificate;
      }
      const authErr = socket.authorizationError;
      finish({
        ok: true,
        chain,
        authorized: socket.authorized,
        ...(authErr ? { authorizationError: String(authErr) } : {}),
        ms: Date.now() - start,
      });
    });
    socket.setTimeout(timeoutMs, () => finish({ ok: false, chain: [], authorized: false, error: 'timeout' }));
    socket.on('error', (e) => finish({ ok: false, chain: [], authorized: false, error: errMsg(e) }));
  });
}

function request(url: string, opts: { timeoutMs: number; verify: boolean; headers?: Record<string, string> }): Promise<HttpResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(
      u,
      {
        method: 'GET',
        headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml,*/*', 'Accept-Encoding': 'identity', ...(opts.headers ?? {}) },
        rejectUnauthorized: opts.verify,
        timeout: opts.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (d: Buffer) => {
          if (size < MAX_BODY) chunks.push(d);
          size += d.length;
          if (size >= MAX_BODY) res.destroy();
        });
        const end = () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
          resolve({
            ok: true,
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? '',
            headers,
            body: Buffer.concat(chunks).toString('utf8'),
            ms: Date.now() - start,
          });
        };
        res.on('end', end);
        res.on('close', end);
        res.on('error', end);
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ ok: false, error: errMsg(e), ms: Date.now() - start }));
    req.end();
  });
}

function wsHandshakeRaw(url: string, timeoutMs: number): Promise<WsResult> {
  return new Promise((resolve) => {
    const u = new URL(url);
    const secure = u.protocol === 'wss:';
    const target = new URL(u.toString());
    target.protocol = secure ? 'https:' : 'http:';
    const mod = secure ? https : http;
    let done = false;
    const finish = (r: WsResult) => {
      if (!done) {
        done = true;
        resolve(r);
      }
    };
    const req = mod.request(target, {
      method: 'GET',
      headers: {
        'User-Agent': UA,
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': randomBytes(16).toString('base64'),
        Origin: `${target.protocol}//${target.host}`,
      },
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    req.on('upgrade', (res, socket) => {
      socket.destroy();
      finish({ ok: true, upgraded: true, status: res.statusCode ?? 101 });
    });
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (d: Buffer) => chunks.push(d));
      res.on('end', () => finish({ ok: true, upgraded: false, status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY) }));
      res.on('error', () => finish({ ok: true, upgraded: false, status: res.statusCode ?? 0 }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => finish({ ok: false, upgraded: false, error: errMsg(e) }));
    req.end();
  });
}

function memo<T>(fn: (key: string) => Promise<T>): (key: string) => Promise<T> {
  const cache = new Map<string, Promise<T>>();
  return (key) => {
    let p = cache.get(key);
    if (!p) {
      p = fn(key);
      cache.set(key, p);
    }
    return p;
  };
}

export interface NodeCtxOptions {
  dataDir?: string;
}

/** The real context: Node networking + Windows/OS access. Network probes are memoized. */
export function createNodeCtx(opts: NodeCtxOptions = {}): Ctx {
  const dataDir = opts.dataDir ?? defaultDataDir();
  const tlsMemo = memo((key) => {
    const i = key.lastIndexOf(':');
    return tlsProbeRaw(key.slice(0, i), Number(key.slice(i + 1)), 10000);
  });
  const userEnvMemo = memo(async (name) => {
    if (process.platform !== 'win32') return undefined;
    const r = await execCmd('reg', ['query', 'HKCU\\Environment', '/v', name], 10000);
    if (r.code !== 0) return undefined;
    const m = new RegExp(`^\\s*${name.replace(/[^\w]/g, '')}\\s+REG_(?:EXPAND_)?SZ\\s+(.*)$`, 'im').exec(r.stdout);
    return m?.[1]?.trim() || undefined;
  });
  let certsPromise: ReturnType<Ctx['getNetfreeCerts']> | null = null;

  async function loadCerts(): ReturnType<Ctx['getNetfreeCerts']> {
    const certDir = path.join(dataDir, 'certs');
    const certs: OfficialCert[] = [];
    let fromNet = 0;
    let lastErr: string | undefined;
    await Promise.all(
      NETFREE_CERT_FILES.map(async (file) => {
        const base = path.basename(file);
        const cachePath = path.join(certDir, base);
        const url = NETFREE_CERT_BASE + file;
        let pem: string | null = null;
        let secure = true;
        let res = await request(url, { timeoutMs: 10000, verify: true });
        if (!res.ok && /CERT|SELF_SIGNED|ISSUER|certificate/i.test(res.error ?? '')) {
          secure = false;
          res = await request(url, { timeoutMs: 10000, verify: false });
        }
        if (res.ok && res.status === 200 && res.body?.includes('BEGIN CERTIFICATE')) {
          if (acceptDownloadedCert(res.body, secure)) {
            pem = res.body;
            fromNet++;
            try {
              await fs.mkdir(certDir, { recursive: true });
              await fs.writeFile(cachePath, pem, 'utf8');
            } catch {
              /* cache is best-effort */
            }
          } else {
            lastErr = `${base}: rejected (not a pinned Netfree root)`;
          }
        } else {
          lastErr = res.error ?? `HTTP ${res.status}`;
        }
        if (!pem) {
          const cached = await fs.readFile(cachePath, 'utf8').catch(() => null);
          if (cached && acceptDownloadedCert(cached, true)) pem = cached;
        }
        if (pem) {
          try {
            certs.push(officialCertFromPem(base, pem));
          } catch {
            /* ignore */
          }
        }
      }),
    );
    certs.sort((a, b) => NETFREE_CERT_FILES.findIndex((f) => f.endsWith(a.name)) - NETFREE_CERT_FILES.findIndex((f) => f.endsWith(b.name)));
    const source = certs.length === 0 ? 'none' : fromNet > 0 ? 'network' : 'cache';
    return { certs, source, ...(lastErr && certs.length < NETFREE_CERT_FILES.length ? { error: lastErr } : {}) };
  }

  return {
    platform: process.platform,
    env: process.env,
    homeDir: os.homedir(),
    dataDir,
    async dnsLookup(host) {
      try {
        const r = await dnsp.lookup(host, { all: true });
        return { addresses: r.map((a) => a.address) };
      } catch (e) {
        return { addresses: [], error: errMsg(e) };
      }
    },
    tcpConnect(host, port, timeoutMs = 8000) {
      return new Promise((resolve) => {
        const start = Date.now();
        const s = net.connect({ host, port });
        const done = (r: { ok: boolean; ms?: number; error?: string }) => {
          s.destroy();
          resolve(r);
        };
        s.setTimeout(timeoutMs, () => done({ ok: false, error: 'timeout' }));
        s.on('connect', () => done({ ok: true, ms: Date.now() - start }));
        s.on('error', (e) => done({ ok: false, error: errMsg(e) }));
      });
    },
    tlsProbe: (host, port) => tlsMemo(`${host}:${port}`),
    // Diagnostic GET: verification off so a block page / note can be read even when Node does not
    // trust Netfree yet. No credentials or cookies are ever sent.
    httpGet: (url, timeoutMs = 15000) => request(url, { timeoutMs, verify: false }),
    wsHandshake: (url, timeoutMs = 15000) => wsHandshakeRaw(url, timeoutMs),
    exec: (file, args, timeoutMs) => execCmd(file, args, timeoutMs),
    readFile: (p) => fs.readFile(p, 'utf8').catch(() => null),
    fileExists: (p) =>
      fs
        .stat(p)
        .then(() => true)
        .catch(() => false),
    listDir: (p) => fs.readdir(p).catch(() => []),
    getUserEnv: (name) => userEnvMemo(name),
    getNetfreeCerts() {
      certsPromise ??= loadCerts();
      return certsPromise;
    },
  };
}


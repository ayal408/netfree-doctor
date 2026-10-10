import type { CertInfo, CheckResult, Ctx, OfficialCert } from '../types.js';
import { bundleThumbprints, combinePem, isNetfreeName, normalizeThumbprint } from '../parsers/certs.js';

/** Hosts used to detect TLS interception. All are allowed on Netfree. */
export const PROBE_HOSTS = ['www.google.com', 'github.com', 'pypi.org'] as const;

export function joinPath(ctx: Ctx, ...parts: string[]): string {
  const sep = ctx.platform === 'win32' ? '\\' : '/';
  return parts
    .filter((p) => p.length > 0)
    .map((p, i) => (i === 0 ? p.replace(/[\\/]+$/, '') : p.replace(/^[\\/]+|[\\/]+$/g, '')))
    .join(sep);
}

/** Path of the combined Netfree PEM written by the Node fix. */
export function bundlePath(ctx: Ctx): string {
  return joinPath(ctx, ctx.dataDir, 'netfree-ca.pem');
}

/**
 * Root certificate the *live* Netfree chain anchors to, or null when not on Netfree / unreachable.
 * If the server sends the self-signed root it is used directly; otherwise the root is looked up
 * among the official certificates by the issuer CN of the last certificate in the chain.
 */
export async function liveNetfreeRoot(ctx: Ctx): Promise<CertInfo | null> {
  for (const host of PROBE_HOSTS) {
    const r = await ctx.tlsProbe(host, 443);
    if (!r.ok || r.chain.length === 0) continue;
    const last = r.chain[r.chain.length - 1];
    if (!last || !isNetfreeName(last.issuer)) return null; // reachable but not intercepted
    const selfSigned = last.subject.CN === last.issuer.CN && last.subject.O === last.issuer.O;
    if (selfSigned) return last;
    const { certs } = await ctx.getNetfreeCerts();
    const off = certs.find((c) => c.subjectCN === last.issuer.CN);
    if (!off) return null;
    return { subject: { CN: off.subjectCN }, issuer: { CN: off.subjectCN }, sha1: off.sha1, sha256: off.sha256, pem: off.pem };
  }
  return null;
}

export interface WantedCert {
  sha1: string;
  subjectCN: string;
}

/** Certificates a bundle should contain: the live root first, then the official roots. */
export async function wantedCerts(ctx: Ctx): Promise<{ live: WantedCert | null; official: OfficialCert[] }> {
  const live = await liveNetfreeRoot(ctx);
  const { certs } = await ctx.getNetfreeCerts();
  return { live: live ? { sha1: live.sha1, subjectCN: live.subject.CN ?? '?' } : null, official: certs };
}

export type Coverage = 'full' | 'live-only' | 'partial' | 'none';

/** How well a PEM bundle covers the Netfree roots. */
export function coverageOf(bundleText: string, live: WantedCert | null, official: OfficialCert[]): Coverage {
  const have = bundleThumbprints(bundleText);
  const liveOk = live ? have.has(normalizeThumbprint(live.sha1)) : undefined;
  const officialHave = official.filter((c) => have.has(normalizeThumbprint(c.sha1))).length;
  const allOfficial = official.length > 0 && officialHave === official.length;
  if (liveOk === false) return officialHave > 0 ? 'partial' : 'none';
  if (allOfficial) return 'full';
  if (liveOk === true) return 'live-only';
  return officialHave > 0 ? 'partial' : 'none';
}

/** True if this coverage is enough for things to work today. */
export function coverageWorks(c: Coverage): boolean {
  return c === 'full' || c === 'live-only';
}

/** PEM with all Netfree roots we know about (official + live root). */
export async function netfreePem(ctx: Ctx): Promise<string> {
  const { certs } = await ctx.getNetfreeCerts();
  const parts = certs.map((c) => c.pem);
  const live = await liveNetfreeRoot(ctx);
  if (live?.pem) parts.push(live.pem);
  return combinePem(parts);
}

/** Reads an environment variable from the process and (on Windows) the persistent user scope. */
export async function readEnvVar(ctx: Ctx, name: string): Promise<{ process?: string; user?: string; effective?: string }> {
  const proc = ctx.env[name];
  const user = await ctx.getUserEnv(name);
  const out: { process?: string; user?: string; effective?: string } = {};
  if (proc) out.process = proc;
  if (user) out.user = user;
  const eff = proc ?? user;
  if (eff) out.effective = eff;
  return out;
}

export function notWindows(ctx: Ctx): CheckResult | null {
  if (ctx.platform === 'win32') return null;
  return {
    status: 'info',
    summaryHe: 'בדיקה זו רלוונטית ל-Windows בלבד.',
    summaryEn: 'This check is Windows-only.',
  };
}

export function stripQuotes(s: string): string {
  const t = s.trim();
  return t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) ? t.slice(1, -1) : t;
}

/** Runs npm on any platform (npm is a .cmd shim on Windows). */
export function execNpm(ctx: Ctx, args: string[], timeoutMs?: number) {
  return ctx.platform === 'win32' ? ctx.exec('cmd.exe', ['/d', '/c', 'npm', ...args], timeoutMs) : ctx.exec('npm', args, timeoutMs);
}

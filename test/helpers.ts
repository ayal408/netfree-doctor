import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { CertInfo, Ctx, ExecResult, HttpResult, OfficialCert, TlsProbeResult, WsResult } from '../src/core/types.js';
import { certInfoFromPem, officialCertFromPem } from '../src/core/parsers/certs.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function fixture(name: string): string {
  return readFileSync(path.join(here, 'fixtures', name), 'utf8');
}

export const ROOT_RSA_PEM = fixture('root_ca_rsa.crt');
export const ROOT_X2_RSA_PEM = fixture('root_ca_x2_rsa.crt');
export const ROOT_ED25519_PEM = fixture('root_ca_ed25519.crt');

export const OFFICIAL: OfficialCert[] = [
  officialCertFromPem('root_ca_x2_rsa.crt', ROOT_X2_RSA_PEM),
  officialCertFromPem('root_ca_rsa.crt', ROOT_RSA_PEM),
  officialCertFromPem('root_ca_ed25519.crt', ROOT_ED25519_PEM),
];

/** A chain as Netfree presents it today: leaf <- node intermediate <- intermediate <- root RSA. */
export function netfreeChain(host = 'www.google.com'): CertInfo[] {
  const root = certInfoFromPem(ROOT_RSA_PEM);
  return [
    { subject: { CN: host }, issuer: { O: 'NetFree WiFree3', CN: 'NetFree Node Intermediate CA, NetFree WiFree3' }, sha1: 'AA', sha256: 'AA' },
    {
      subject: { O: 'NetFree WiFree3', CN: 'NetFree Node Intermediate CA, NetFree WiFree3' },
      issuer: { C: 'IL', O: 'NetFree', OU: 'netfree.link', CN: 'NetFree Intermediate CA 2026#09' },
      sha1: 'BB',
      sha256: 'BB',
    },
    {
      subject: { C: 'IL', O: 'NetFree', OU: 'netfree.link', CN: 'NetFree Intermediate CA 2026#09' },
      issuer: { C: 'IL', O: 'NetFree', OU: 'netfree.link', CN: 'NetFree Root CA 1990-2200 RSA' },
      sha1: 'CC',
      sha256: 'CC',
    },
    root,
  ];
}

export function publicChain(host = 'www.google.com'): CertInfo[] {
  return [
    { subject: { CN: host }, issuer: { C: 'US', O: 'Google Trust Services', CN: 'WE2' }, sha1: '11', sha256: '11' },
    { subject: { C: 'US', O: 'Google Trust Services', CN: 'WE2' }, issuer: { C: 'US', O: 'Google Trust Services LLC', CN: 'GTS Root R4' }, sha1: '22', sha256: '22' },
  ];
}

export type ExecHandler = (file: string, args: string[]) => ExecResult | undefined;

export interface FakeOptions {
  platform?: NodeJS.Platform;
  env?: Record<string, string | undefined>;
  userEnv?: Record<string, string>;
  files?: Record<string, string>;
  dirs?: Record<string, string[]>;
  tls?: (host: string) => TlsProbeResult;
  http?: (url: string) => HttpResult;
  ws?: (url: string) => WsResult;
  dns?: (host: string) => { addresses: string[]; error?: string };
  exec?: ExecHandler;
  certs?: OfficialCert[];
}

export const NOT_FOUND: ExecResult = { code: -1, stdout: '', stderr: '', error: 'not found' };

export function ok(stdout = '', stderr = ''): ExecResult {
  return { code: 0, stdout, stderr };
}

export function fakeCtx(o: FakeOptions = {}): Ctx & { execLog: string[] } {
  const files = o.files ?? {};
  const execLog: string[] = [];
  const norm = (p: string) => p.toLowerCase();
  const fileMap = new Map(Object.entries(files).map(([k, v]) => [norm(k), v]));
  const dirMap = new Map(Object.entries(o.dirs ?? {}).map(([k, v]) => [norm(k), v]));
  return {
    platform: o.platform ?? 'win32',
    env: o.env ?? {},
    homeDir: 'C:\\Users\\test',
    dataDir: 'C:\\Users\\test\\.netfree-doctor',
    execLog,
    async dnsLookup(host) {
      return o.dns ? o.dns(host) : { addresses: ['1.2.3.4'] };
    },
    async tcpConnect() {
      return { ok: true, ms: 5 };
    },
    async tlsProbe(host) {
      return o.tls ? o.tls(host) : { ok: true, chain: netfreeChain(host), authorized: true };
    },
    async httpGet(url) {
      return o.http ? o.http(url) : { ok: true, status: 200, statusText: 'OK', headers: {}, body: '<html></html>' };
    },
    async wsHandshake(url) {
      return o.ws ? o.ws(url) : { ok: true, upgraded: true, status: 101 };
    },
    async exec(file, args) {
      execLog.push([file, ...args].join(' '));
      return o.exec?.(file, args) ?? NOT_FOUND;
    },
    async readFile(p) {
      return fileMap.get(norm(p)) ?? null;
    },
    async fileExists(p) {
      return fileMap.has(norm(p)) || dirMap.has(norm(p));
    },
    async listDir(p) {
      return dirMap.get(norm(p)) ?? [];
    },
    async getUserEnv(name) {
      return o.userEnv?.[name];
    },
    async getNetfreeCerts() {
      const certs = o.certs ?? OFFICIAL;
      return { certs, source: certs.length ? 'network' : 'none' };
    },
  };
}

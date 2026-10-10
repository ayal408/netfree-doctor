/**
 * Core types for the netfree-doctor check engine.
 *
 * The engine is pure: every interaction with the network, the file system or the OS
 * goes through the {@link Ctx} interface, so checks can be unit-tested with fakes.
 */

export type Status = 'ok' | 'warn' | 'fail' | 'info';

/** A primitive, reversible operation that a fix performs. */
export type FixOp =
  | {
      kind: 'writeFile';
      path: string;
      content: string;
      descriptionHe: string;
      descriptionEn: string;
    }
  | {
      kind: 'exec';
      file: string;
      args: string[];
      descriptionHe: string;
      descriptionEn: string;
      /** Command that reverts this op (computed when the plan is built). null = nothing to undo. */
      undo: { file: string; args: string[] } | null;
      /** Files the command may modify; they are backed up before it runs. */
      backupPaths?: string[];
    };

/** A fix offered by a check. `id` is what the user passes to `netfree-doctor fix <id>`. */
export interface FixAction {
  id: string;
  titleHe: string;
  titleEn: string;
  /** Extra preconditions/warnings shown before applying (e.g. "close Firefox first"). */
  noteHe?: string;
  noteEn?: string;
}

export interface CheckResult {
  status: Status;
  summaryHe: string;
  summaryEn: string;
  detailsHe?: string[];
  detailsEn?: string[];
  fix?: FixAction;
  /** Machine-readable extra data (shown in --json). */
  data?: Record<string, unknown>;
}

export interface Check {
  id: string;
  titleHe: string;
  titleEn: string;
  run(ctx: Ctx): Promise<CheckResult>;
}

export interface CheckOutcome extends CheckResult {
  id: string;
  titleHe: string;
  titleEn: string;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Context (injected side effects)
// ---------------------------------------------------------------------------

export interface CertInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  /** SHA-1 fingerprint, upper-case hex without separators. */
  sha1: string;
  sha256: string;
  validTo?: string;
  /** PEM encoding, when available. */
  pem?: string;
}

export interface TlsProbeResult {
  ok: boolean;
  /** Leaf first, root last. */
  chain: CertInfo[];
  /** Whether Node's own CA store (+NODE_EXTRA_CA_CERTS) trusted the chain. */
  authorized: boolean;
  authorizationError?: string;
  error?: string;
  ms?: number;
}

export interface HttpResult {
  ok: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
  ms?: number;
}

export interface WsResult {
  ok: boolean;
  /** 101 on successful upgrade. */
  status?: number;
  upgraded: boolean;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  /** Set when the process could not be started (e.g. ENOENT). */
  error?: string;
}

export interface OfficialCert {
  /** File name on netfree.link, e.g. root_ca_x2_rsa.crt */
  name: string;
  pem: string;
  subjectCN: string;
  sha1: string;
  sha256: string;
}

export interface Ctx {
  platform: NodeJS.Platform;
  /** Current process environment. */
  env: Record<string, string | undefined>;
  homeDir: string;
  /** Directory for the tool's own data (cache, bundle, backups, journal). */
  dataDir: string;

  dnsLookup(host: string): Promise<{ addresses: string[]; error?: string }>;
  tcpConnect(host: string, port: number, timeoutMs?: number): Promise<{ ok: boolean; ms?: number; error?: string }>;
  tlsProbe(host: string, port: number, timeoutMs?: number): Promise<TlsProbeResult>;
  httpGet(url: string, timeoutMs?: number): Promise<HttpResult>;
  wsHandshake(url: string, timeoutMs?: number): Promise<WsResult>;

  exec(file: string, args: string[], timeoutMs?: number): Promise<ExecResult>;
  readFile(path: string): Promise<string | null>;
  fileExists(path: string): Promise<boolean>;
  listDir(path: string): Promise<string[]>;
  /** Persistent user environment variable (HKCU\Environment on Windows). */
  getUserEnv(name: string): Promise<string | undefined>;
  /** Official Netfree root CAs (downloaded from netfree.link and cached). */
  getNetfreeCerts(): Promise<{ certs: OfficialCert[]; source: 'network' | 'cache' | 'none'; error?: string }>;
}

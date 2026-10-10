import type { StoreCert } from './certs.js';

/**
 * Parses the output of `... | ConvertTo-Json`. PowerShell emits a single object (not an array)
 * when there is exactly one item, and nothing at all when there are none.
 * Windows PowerShell 5.1 serializes dates as "\/Date(ms)\/" - those are converted to ISO strings.
 */
export function parsePsJson(stdout: string): Record<string, unknown>[] {
  const text = (stdout.charCodeAt(0) === 0xfeff ? stdout.slice(1) : stdout).trim();
  if (!text) return [];
  const parsed: unknown = JSON.parse(text, (_k, v: unknown) => {
    if (typeof v === 'string') {
      const m = /^\/Date\((-?\d+)(?:[+-]\d+)?\)\/$/.exec(v);
      if (m?.[1]) return new Date(Number(m[1])).toISOString();
    }
    return v;
  });
  if (Array.isArray(parsed)) return parsed.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object');
  if (parsed && typeof parsed === 'object') return [parsed as Record<string, unknown>];
  return [];
}

/** "Microsoft.PowerShell.Security\Certificate::CurrentUser\Root" -> "CurrentUser\Root" */
export function storeFromPsParentPath(p: string): string {
  const idx = p.indexOf('::');
  return idx >= 0 ? p.slice(idx + 2) : p;
}

export const STORE_QUERY_PS =
  "$ErrorActionPreference='SilentlyContinue'; " +
  "Get-ChildItem Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\Root | " +
  "Where-Object { $_.Subject -like '*NetFree*' -or $_.Issuer -like '*NetFree*' } | " +
  'Select-Object PSParentPath, Subject, Thumbprint, NotAfter | ConvertTo-Json -Compress';

export function parseStoreCerts(stdout: string): StoreCert[] {
  return parsePsJson(stdout).map((o) => {
    const notAfter = typeof o.NotAfter === 'string' ? o.NotAfter : undefined;
    return {
      store: storeFromPsParentPath(String(o.PSParentPath ?? '')),
      subject: String(o.Subject ?? ''),
      thumbprint: String(o.Thumbprint ?? ''),
      ...(notAfter ? { notAfter } : {}),
    };
  });
}

import { X509Certificate } from 'node:crypto';
import type { CertInfo, OfficialCert } from '../types.js';

/** Official Netfree root CA files (both generations are published on netfree.link). */
export const NETFREE_CERT_BASE = 'https://netfree.link/cacert/united/';
export const NETFREE_CERT_FILES: readonly string[] = [
  // X2 generation
  'x2/root_ca_x2_rsa.crt',
  'x2/root_ca_x2_ed25519.crt',
  'x2/root_ca_x2_prime256v1.crt',
  'x2/root_ca_x2_secp384r1.crt',
  'x2/root_ca_x2_rsa_2037.crt',
  // First generation (live chains on Netfree currently still anchor here, e.g. "NetFree Root CA 1990-2200 RSA")
  'root_ca_rsa.crt',
  'root_ca_ed25519.crt',
  'root_ca_prime256v1.crt',
  'root_ca_secp384r1.crt',
  'root_ca_rsa_2037.crt',
];

export const NETFREE_INSTALL_GUIDE = 'https://netfree.link/wiki/';

const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Splits a PEM bundle into individual certificate blocks. */
export function splitPem(text: string): string[] {
  return (text.match(PEM_RE) ?? []).map((b) => b.replace(/\r\n/g, '\n').trim() + '\n');
}

/** Normalizes a fingerprint/thumbprint: "aa:bb cc" -> "AABBCC". */
export function normalizeThumbprint(s: string): string {
  return s.replace(/[^0-9a-f]/gi, '').toUpperCase();
}

/**
 * Parses an X.500 distinguished name in either style:
 *   "CN=foo, OU=bar, O=Baz"   (Windows / PowerShell)
 *   "C=IL\nST=...\nO=NetFree" (Node X509Certificate.subject)
 * Supports double-quoted values containing commas.
 */
export function parseDn(dn: string): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  const s = dn.trim();
  while (i < s.length) {
    while (i < s.length && /[\s,;\n]/.test(s[i] ?? '')) i++;
    const eq = s.indexOf('=', i);
    if (eq < 0) break;
    const key = s.slice(i, eq).trim();
    i = eq + 1;
    let value = '';
    if (s[i] === '"') {
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\' && i + 1 < s.length) i++;
        value += s[i];
        i++;
      }
      i++; // closing quote
      while (i < s.length && s[i] !== ',' && s[i] !== '\n') i++;
    } else {
      while (i < s.length && s[i] !== ',' && s[i] !== '\n') {
        if (s[i] === '\\' && i + 1 < s.length) i++;
        value += s[i];
        i++;
      }
      value = value.trim();
    }
    if (key) out[key] = value;
  }
  return out;
}

/** True if a subject/issuer record belongs to Netfree. */
export function isNetfreeName(name: Record<string, string> | undefined): boolean {
  if (!name) return false;
  return /netfree/i.test(name.O ?? '') || /netfree/i.test(name.CN ?? '');
}

/** Index of the first Netfree certificate in a chain, or -1. */
export function findNetfreeInChain(chain: CertInfo[]): number {
  return chain.findIndex((c) => isNetfreeName(c.issuer) || isNetfreeName(c.subject));
}

export function certInfoFromPem(pem: string): CertInfo {
  const x = new X509Certificate(pem);
  return {
    subject: parseDn(x.subject),
    issuer: parseDn(x.issuer),
    sha1: normalizeThumbprint(x.fingerprint),
    sha256: normalizeThumbprint(x.fingerprint256),
    validTo: x.validTo,
    pem: x.toString(),
  };
}

export function officialCertFromPem(name: string, pem: string): OfficialCert {
  const info = certInfoFromPem(pem);
  return { name, pem: info.pem ?? pem, subjectCN: info.subject.CN ?? '', sha1: info.sha1, sha256: info.sha256 };
}

/** SHA-1 thumbprints of all certificates in a PEM bundle (invalid blocks are skipped). */
export function bundleThumbprints(text: string): Set<string> {
  const out = new Set<string>();
  for (const block of splitPem(text)) {
    try {
      out.add(certInfoFromPem(block).sha1);
    } catch {
      /* skip */
    }
  }
  return out;
}

/** Which of the wanted certificates are present in a PEM bundle. */
export function bundleCoverage(
  bundleText: string,
  wanted: { sha1: string; subjectCN: string }[],
): { present: string[]; missing: string[] } {
  const have = bundleThumbprints(bundleText);
  const present: string[] = [];
  const missing: string[] = [];
  for (const w of wanted) (have.has(normalizeThumbprint(w.sha1)) ? present : missing).push(w.subjectCN);
  return { present, missing };
}

export interface StoreCert {
  /** e.g. "CurrentUser\\Root" */
  store: string;
  subject: string;
  thumbprint: string;
  notAfter?: string;
}

export interface StoreMatch {
  present: { cert: OfficialCert; stores: string[] }[];
  missing: OfficialCert[];
  /** Matched by subject CN only (different thumbprint, e.g. re-issued). */
  subjectOnly: { cert: OfficialCert; stores: string[] }[];
}

/** Matches official Netfree roots against certificates from the Windows root stores. */
export function matchStoreCerts(store: StoreCert[], official: OfficialCert[]): StoreMatch {
  const res: StoreMatch = { present: [], missing: [], subjectOnly: [] };
  for (const cert of official) {
    const byThumb = store.filter((s) => normalizeThumbprint(s.thumbprint) === normalizeThumbprint(cert.sha1));
    if (byThumb.length) {
      res.present.push({ cert, stores: [...new Set(byThumb.map((s) => s.store))] });
      continue;
    }
    const bySubject = store.filter((s) => parseDn(s.subject).CN === cert.subjectCN);
    if (bySubject.length) {
      res.subjectOnly.push({ cert, stores: [...new Set(bySubject.map((s) => s.store))] });
      continue;
    }
    res.missing.push(cert);
  }
  return res;
}

/** Builds a combined PEM bundle: base certificates first, then extras, without duplicates. */
export function combinePem(parts: string[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of parts) {
    for (const block of splitPem(part)) {
      let key: string;
      try {
        key = certInfoFromPem(block).sha1;
      } catch {
        key = block;
      }
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(block);
    }
  }
  return out.join('');
}

/**
 * SHA-256 fingerprints of the official Netfree roots (verified 2026-10-10 against
 * netfree.link/cacert/united/). Downloads matching a pin are accepted even when the download
 * connection itself could not be verified (chicken-and-egg: Node may not trust Netfree yet).
 * Certificates not in this list are only accepted over a verified TLS connection.
 */
export const PINNED_NETFREE_SHA256: ReadonlySet<string> = new Set([
  '22D61B27B728865BDD8CF46EBA5677D2A9DE0EF059236B67C1E438ABE6BB33BC', // x2/root_ca_x2_rsa.crt
  '17031B612D4BC0DB25DE1999F167F2E6DBAC181F638606849AA45EA1F13FFC40', // x2/root_ca_x2_ed25519.crt
  '336A31840C0500FE32FAC5759D30610DD66F5A5D8E606F0EF2EBA3E218C73C06', // x2/root_ca_x2_prime256v1.crt
  'FCE033C1057EE152163251BC1EF9852C3F7AE813AB873BA18DE46B6E3763AFB7', // x2/root_ca_x2_secp384r1.crt
  'AE1EFD860D72348E8B6A65FA2531359E86D4B26AE87FAD510ADC818E67E9FB71', // x2/root_ca_x2_rsa_2037.crt
  'A5390FD33CEA846DC02C34F618ACCB02C18A6A4E1963695A665635163275B76B', // root_ca_rsa.crt
  '6A0442C5DEB560C0902533395B33D9FAAB4F73C80F87F398DB9C81CEC7DB8A32', // root_ca_ed25519.crt
  '230783E003FC5E57AA61D52EDD3B764AD5FF9378636E60E194501EB33CEE1671', // root_ca_prime256v1.crt
  'DE34092171B2A077CE9CA0D72C201A8061067B86D251570E2A991DEAA67538B6', // root_ca_secp384r1.crt
  '2227FBD982918C9E9540C823453A08ED15FF0ED3F69523D1DF4F8C985F267C92', // root_ca_rsa_2037.crt
]);

/** Accepts a downloaded certificate only if it is a Netfree root and pinned (or fetched securely). */
export function acceptDownloadedCert(pem: string, fetchedSecurely: boolean): boolean {
  try {
    const x = new X509Certificate(pem);
    if (!x.ca || !/netfree/i.test(x.subject)) return false;
    return fetchedSecurely || PINNED_NETFREE_SHA256.has(normalizeThumbprint(x.fingerprint256));
  } catch {
    return false;
  }
}

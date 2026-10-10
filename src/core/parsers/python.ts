/** Parsers for Python launcher / pip output. */

export interface PythonInstall {
  path: string;
  version?: string;
  isDefault: boolean;
  /** The Microsoft Store "App Execution Alias" stub (often not a real Python). */
  isStoreStub: boolean;
}

/**
 * Parses `py -0p`. Formats seen:
 *   " -V:3.14[-64] *   C:\...\python.exe"   (new launcher)
 *   " -3.12-64 *       C:\...\python.exe"   (older launcher)
 */
export function parsePyLauncherList(stdout: string): PythonInstall[] {
  const out: PythonInstall[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^\s*-(?:V:)?(\S+?)\s+(\*\s+)?([A-Za-z]:\\.+?\.exe)\s*$/.exec(line);
    if (!m?.[3]) continue;
    const version = (m[1] ?? '').replace(/\[.*\]$/, '');
    out.push({ path: m[3], version, isDefault: !!m[2], isStoreStub: isStoreStub(m[3]) });
  }
  return out;
}

export function isStoreStub(p: string): boolean {
  return /\\Microsoft\\WindowsApps\\/i.test(p);
}

/** Parses `where python` output. */
export function parseWhere(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => /^[A-Za-z]:\\/.test(l));
}

/** Parses `pip config list`: lines like  global.cert='C:\path'  */
export function parsePipConfigList(stdout: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^\s*([\w.-]+)\s*=\s*(.*)$/.exec(line);
    if (!m?.[1] || m[2] === undefined) continue;
    let v = m[2].trim();
    if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) {
      // pip prints Python repr(): backslashes are doubled inside quotes.
      v = v.slice(1, -1).replace(/\\\\/g, '\\');
    }
    out[m[1]] = v;
  }
  return out;
}

/**
 * Python snippet run by the Python check (with -E; the current directory is removed from
 * sys.path first). Prints a single JSON line. It performs real TLS handshakes to pypi.org:
 *  - with certifi only (what requests uses by default),
 *  - with the default/system store (strict and, for diagnosis, non-strict X.509 flags),
 *  - with `requests` itself when installed (honours REQUESTS_CA_BUNDLE / pip-system-certs).
 */
export const PY_PROBE = String.raw`
import sys
sys.path = [p for p in sys.path if p not in ("", ".")]
import json, ssl, socket, importlib.util as u
r = {"version": sys.version.split()[0], "executable": sys.executable}
def has(m):
    try:
        return u.find_spec(m) is not None
    except Exception:
        return False
r["truststore"] = has("truststore")
r["pip_system_certs"] = has("pip_system_certs")
r["has_pip"] = has("pip")
r["requests_installed"] = has("requests")
cert = None
try:
    import certifi
    cert = certifi.where()
except Exception:
    try:
        from pip._vendor import certifi as c2
        cert = c2.where()
    except Exception:
        pass
r["certifi"] = cert
try:
    import pip
    r["pip_version"] = pip.__version__
except Exception:
    pass
STRICT = getattr(ssl, "VERIFY_X509_STRICT", 0)
r["x509_strict_default"] = bool(STRICT and ssl.create_default_context().verify_flags & STRICT)
def err(e):
    return (type(e).__name__ + ": " + str(e))[:240]
def probe(cafile, strict=True):
    try:
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        if not strict and STRICT:
            ctx.verify_flags &= ~STRICT
        with socket.create_connection(("pypi.org", 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname="pypi.org"):
                return "ok"
    except Exception as e:
        return err(e)
r["probe_certifi"] = probe(cert) if cert else None
r["probe_system"] = probe(None)
r["probe_system_nonstrict"] = probe(None, strict=False) if r["probe_system"] != "ok" and r["x509_strict_default"] else None
if r["requests_installed"]:
    try:
        import requests
        requests.head("https://pypi.org/simple/", timeout=8)
        r["probe_requests"] = "ok"
    except Exception as e:
        r["probe_requests"] = err(e)
print(json.dumps(r))
`;

export interface PyProbe {
  version: string;
  executable: string;
  truststore: boolean;
  pip_system_certs: boolean;
  has_pip: boolean;
  requests_installed: boolean;
  certifi: string | null;
  pip_version?: string;
  x509_strict_default: boolean;
  probe_certifi: string | null;
  probe_system: string;
  probe_system_nonstrict: string | null;
  probe_requests?: string;
}

/** True if a TLS error is the Python 3.13+ strict-X.509 "missing key usage" rejection. */
export function isKeyUsageError(msg: string | null | undefined): boolean {
  return !!msg && /key usage/i.test(msg);
}

export function parsePyProbe(stdout: string): PyProbe | null {
  const line = stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .reverse()
    .find((l) => l.startsWith('{'));
  if (!line) return null;
  try {
    return JSON.parse(line) as PyProbe;
  } catch {
    return null;
  }
}

/** Compares dotted versions: returns true if a >= b. */
export function versionGte(a: string | undefined, b: string): boolean {
  if (!a) return false;
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return true;
}

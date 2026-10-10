import { describe, expect, it } from 'vitest';
import { netfreeCheck } from '../src/core/checks/netfree.js';
import { windowsStoreCheck } from '../src/core/checks/windowsStore.js';
import { firefoxCheck } from '../src/core/checks/firefox.js';
import { nodeCheck } from '../src/core/checks/node.js';
import { pythonCheck } from '../src/core/checks/python.js';
import { gitCheck } from '../src/core/checks/git.js';
import { javaCheck } from '../src/core/checks/java.js';
import { androidCheck } from '../src/core/checks/android.js';
import { runChecks } from '../src/core/engine.js';
import type { Check } from '../src/core/types.js';
import { fakeCtx, NOT_FOUND, ok, OFFICIAL, publicChain, ROOT_ED25519_PEM, ROOT_RSA_PEM, ROOT_X2_RSA_PEM } from './helpers.js';

const ALL_PEM = ROOT_RSA_PEM + ROOT_X2_RSA_PEM + ROOT_ED25519_PEM;

describe('netfree check', () => {
  it('detects Netfree interception from the issuer chain', async () => {
    const r = await netfreeCheck.run(fakeCtx());
    expect(r.status).toBe('ok');
    expect(r.data?.onNetfree).toBe(true);
    expect(r.data?.root).toBe('NetFree Root CA 1990-2200 RSA');
    expect(r.detailsHe?.[0]).toContain('NetFree WiFree3');
  });

  it('reports info when certificates are original', async () => {
    const r = await netfreeCheck.run(fakeCtx({ tls: (h) => ({ ok: true, chain: publicChain(h), authorized: true }) }));
    expect(r.status).toBe('info');
    expect(r.data?.onNetfree).toBe(false);
  });

  it('fails when nothing is reachable', async () => {
    const r = await netfreeCheck.run(fakeCtx({ tls: () => ({ ok: false, chain: [], authorized: false, error: 'ECONNREFUSED' }) }));
    expect(r.status).toBe('fail');
  });
});

function storeJson(thumbs: string[]): string {
  return JSON.stringify(
    thumbs.map((t) => ({ PSParentPath: 'Microsoft.PowerShell.Security\\Certificate::CurrentUser\\Root', Subject: 'CN=x, O=NetFree', Thumbprint: t })),
  );
}

describe('windows store check', () => {
  const ps = (stdout: string) => (file: string) => (file === 'powershell.exe' ? ok(stdout) : undefined);

  it('ok when all official roots are installed', async () => {
    const r = await windowsStoreCheck.run(fakeCtx({ exec: ps(storeJson(OFFICIAL.map((c) => c.sha1))) }));
    expect(r.status).toBe('ok');
  });

  it('warn when the live root is present but some official roots are missing', async () => {
    const r = await windowsStoreCheck.run(fakeCtx({ exec: ps(storeJson([OFFICIAL[1]!.sha1])) }));
    expect(r.status).toBe('warn');
    expect(r.data?.missing).toEqual(['root_ca_x2_rsa.crt', 'root_ca_ed25519.crt']);
  });

  it('fail when the live root is missing (no automatic fix for root CAs)', async () => {
    const r = await windowsStoreCheck.run(fakeCtx({ exec: ps('') }));
    expect(r.status).toBe('fail');
    expect(r.fix).toBeUndefined();
    expect(r.detailsHe?.join('\n')).toContain('https://netfree.link/wiki/');
  });

  it('is info-only on non-Windows', async () => {
    expect((await windowsStoreCheck.run(fakeCtx({ platform: 'linux' }))).status).toBe('info');
  });
});

describe('firefox check', () => {
  const base = 'C:\\Users\\test\\AppData\\Roaming\\Mozilla\\Firefox';
  const ini = '[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n';
  const prof = `${base}\\Profiles\\abc.default-release`;
  const env = { APPDATA: 'C:\\Users\\test\\AppData\\Roaming' };

  it('info when Firefox is not installed', async () => {
    expect((await firefoxCheck.run(fakeCtx({ env }))).status).toBe('info');
  });

  it('fail + fix when enterprise roots is explicitly false', async () => {
    const r = await firefoxCheck.run(
      fakeCtx({ env, files: { [`${base}\\profiles.ini`]: ini, [`${prof}\\prefs.js`]: 'user_pref("security.enterprise_roots.enabled", false);\n' }, dirs: { [prof]: [] } }),
    );
    expect(r.status).toBe('fail');
    expect(r.fix?.id).toBe('firefox-enterprise-roots');
  });

  it('user.js overrides prefs.js', async () => {
    const r = await firefoxCheck.run(
      fakeCtx({
        env,
        files: {
          [`${base}\\profiles.ini`]: ini,
          [`${prof}\\prefs.js`]: 'user_pref("security.enterprise_roots.enabled", false);\n',
          [`${prof}\\user.js`]: 'user_pref("security.enterprise_roots.enabled", true);\n',
        },
        dirs: { [prof]: [] },
      }),
    );
    expect(r.status).toBe('ok');
  });

  it('warn when unset', async () => {
    const r = await firefoxCheck.run(fakeCtx({ env, files: { [`${base}\\profiles.ini`]: ini }, dirs: { [prof]: [] } }));
    expect(r.status).toBe('warn');
  });
});

describe('node check', () => {
  const npm = (cafile = 'null', strict = 'true') => (file: string, args: string[]) => {
    if (file !== 'cmd.exe') return undefined;
    if (args.includes('cafile')) return ok(cafile + '\n');
    if (args.includes('strict-ssl')) return ok(strict + '\n');
    return undefined;
  };

  it('fail + fix when NODE_EXTRA_CA_CERTS is not set', async () => {
    const r = await nodeCheck.run(fakeCtx({ exec: npm() }));
    expect(r.status).toBe('fail');
    expect(r.fix?.id).toBe('node-extra-ca');
  });

  it('ok when NODE_EXTRA_CA_CERTS contains the Netfree roots', async () => {
    const r = await nodeCheck.run(fakeCtx({ env: { NODE_EXTRA_CA_CERTS: 'C:\\nf.pem' }, files: { 'C:\\nf.pem': ALL_PEM }, exec: npm() }));
    expect(r.status).toBe('ok');
    expect(r.data?.coverage).toBe('full');
  });

  it('fail when the file lacks the live root', async () => {
    const r = await nodeCheck.run(fakeCtx({ env: { NODE_EXTRA_CA_CERTS: 'C:\\nf.pem' }, files: { 'C:\\nf.pem': ROOT_X2_RSA_PEM }, exec: npm() }));
    expect(r.status).toBe('fail');
    expect(r.data?.coverage).toBe('partial');
  });

  it('flags strict-ssl=false as dangerous', async () => {
    const r = await nodeCheck.run(fakeCtx({ env: { NODE_EXTRA_CA_CERTS: 'C:\\nf.pem' }, files: { 'C:\\nf.pem': ALL_PEM }, exec: npm('null', 'false') }));
    expect(r.status).toBe('fail');
    expect(r.summaryEn).toMatch(/strict-ssl=false/);
  });

  it('warn when npm cafile lacks Netfree', async () => {
    const r = await nodeCheck.run(
      fakeCtx({ env: { NODE_EXTRA_CA_CERTS: 'C:\\nf.pem' }, files: { 'C:\\nf.pem': ALL_PEM, 'C:\\other.pem': '' }, exec: npm('C:\\other.pem') }),
    );
    expect(r.status).toBe('warn');
  });
});

describe('python check', () => {
  const PY = 'C:\\Python314\\python.exe';
  const probe = (extra: Record<string, unknown>) =>
    JSON.stringify({
      version: '3.14.6',
      executable: PY,
      truststore: false,
      pip_system_certs: false,
      has_pip: true,
      requests_installed: true,
      certifi: 'C:\\certifi\\cacert.pem',
      pip_version: '26.1',
      x509_strict_default: true,
      probe_certifi: 'SSLCertVerificationError: unable to get local issuer certificate',
      probe_system: 'ok',
      probe_system_nonstrict: null,
      probe_requests: 'ok',
      ...extra,
    });
  const exec = (p: string, pipOk = true) => (file: string, args: string[]) => {
    if (file === 'py') return ok(` -V:3.14[-64] *   ${PY}\n`);
    if (file === 'where') return NOT_FOUND;
    if (file === PY && args.includes('-c')) return ok(p);
    if (file === PY && args.includes('index')) return pipOk ? ok('pip (26.1)') : { code: 1, stdout: '', stderr: 'SSL: CERTIFICATE_VERIFY_FAILED' };
    if (file === PY && args.includes('config')) return ok('');
    return undefined;
  };

  it('info when no python', async () => {
    expect((await pythonCheck.run(fakeCtx({ exec: () => NOT_FOUND }))).status).toBe('info');
  });

  it('ok when pip and requests work', async () => {
    const r = await pythonCheck.run(fakeCtx({ exec: exec(probe({})) }));
    expect(r.status).toBe('ok');
  });

  it('fail + fix when pip fails', async () => {
    const r = await pythonCheck.run(fakeCtx({ exec: exec(probe({ probe_requests: 'SSLError: verify failed' }), false) }));
    expect(r.status).toBe('fail');
    expect(r.fix?.id).toBe('python-pip-cert');
  });

  it('explains the Python 3.13+ key-usage issue without offering a useless fix', async () => {
    const ku = 'SSLCertVerificationError: CA cert does not include key usage extension';
    const r = await pythonCheck.run(fakeCtx({ exec: exec(probe({ probe_system: ku, probe_system_nonstrict: 'ok', probe_requests: `SSLError: ${ku}` })) }));
    expect(r.status).toBe('warn');
    expect(r.fix).toBeUndefined();
    expect(r.data?.keyUsageIssue).toBe(true);
    expect(r.detailsHe?.join('\n')).toContain('Key Usage');
  });
});

describe('git check', () => {
  const git = (cfg: Record<string, string>, lsRemoteOk = true) => (file: string, args: string[]) => {
    if (file !== 'git') return undefined;
    if (args[0] === '--version') return ok('git version 2.55.0.windows.1\n');
    if (args[0] === 'ls-remote') return lsRemoteOk ? ok('abc\trefs/heads/master') : { code: 128, stdout: '', stderr: 'fatal: unable to access: SSL certificate problem: self-signed certificate in certificate chain' };
    if (args[0] === 'config') {
      const key = args[args.length - 1]!;
      const v = cfg[key];
      return v === undefined ? { code: 1, stdout: '', stderr: '' } : ok(v + '\n');
    }
    return undefined;
  };

  it('ok with schannel', async () => {
    expect((await gitCheck.run(fakeCtx({ exec: git({ 'http.sslBackend': 'schannel' }) }))).status).toBe('ok');
  });

  it('fail on sslVerify=false (the wrong fix)', async () => {
    const r = await gitCheck.run(fakeCtx({ exec: git({ 'http.sslVerify': 'false' }) }));
    expect(r.status).toBe('fail');
    expect(r.fix?.id).toBe('git-schannel');
  });

  it('ok with an sslCAInfo bundle that includes Netfree', async () => {
    const r = await gitCheck.run(fakeCtx({ exec: git({ 'http.sslCAInfo': 'C:\\b.crt' }), files: { 'C:\\b.crt': ALL_PEM } }));
    expect(r.status).toBe('ok');
  });

  it('fail when openssl backend cannot reach GitHub', async () => {
    const r = await gitCheck.run(fakeCtx({ exec: git({}, false) }));
    expect(r.status).toBe('fail');
    expect(r.fix?.id).toBe('git-schannel');
  });

  it('info when git is missing', async () => {
    expect((await gitCheck.run(fakeCtx({ exec: () => NOT_FOUND }))).status).toBe('info');
  });
});

describe('java + android checks', () => {
  it('java: info with keytool command', async () => {
    const r = await javaCheck.run(
      fakeCtx({ exec: (f, a) => (f === 'where' && a[0] === 'java' ? ok('C:\\jdk\\bin\\java.exe\r\n') : f.endsWith('java.exe') ? { code: 0, stdout: '', stderr: 'openjdk version "21"' } : undefined) }),
    );
    expect(r.status).toBe('info');
    expect(r.detailsEn?.join('\n')).toContain('keytool -importcert -cacerts');
    expect(r.detailsEn?.join('\n')).toContain('Windows-ROOT');
  });

  it('java: ok when Windows-ROOT trust store is configured', async () => {
    const r = await javaCheck.run(
      fakeCtx({
        env: { JAVA_TOOL_OPTIONS: '-Djavax.net.ssl.trustStoreType=Windows-ROOT' },
        exec: (f) => (f === 'where' ? ok('C:\\jdk\\bin\\java.exe\r\n') : { code: 0, stdout: '', stderr: 'openjdk' }),
      }),
    );
    expect(r.status).toBe('ok');
  });

  it('android: detects LDPlayer and points to the Magisk modules', async () => {
    const r = await androidCheck.run(
      fakeCtx({ dirs: { 'C:\\LDPlayer': ['LDPlayer9'] }, files: { 'C:\\LDPlayer\\LDPlayer9\\ldconsole.exe': '' } }),
    );
    expect(r.status).toBe('info');
    expect(r.summaryHe).toContain('LDPlayer');
    expect(r.detailsHe?.join('\n')).toContain('https://github.com/Sivan22/ca-netfree-android14/releases');
    expect(r.fix).toBeUndefined();
  });

  it('android: nothing found', async () => {
    expect((await androidCheck.run(fakeCtx())).summaryEn).toMatch(/No Android emulators/);
  });
});

describe('engine', () => {
  it('turns a crashing check into a fail result and keeps order', async () => {
    const boom: Check = { id: 'boom', titleHe: 'x', titleEn: 'x', run: async () => Promise.reject(new Error('kaboom')) };
    const fine: Check = { id: 'fine', titleHe: 'y', titleEn: 'y', run: async () => ({ status: 'ok', summaryHe: '', summaryEn: '' }) };
    const res = await runChecks(fakeCtx(), [boom, fine]);
    expect(res.map((r) => r.id)).toEqual(['boom', 'fine']);
    expect(res[0]!.status).toBe('fail');
    expect(res[0]!.summaryEn).toContain('kaboom');
  });
});

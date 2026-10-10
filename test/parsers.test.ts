import { describe, expect, it } from 'vitest';
import { explainBlockReason, looksLikeBlock, parseBlockPage, KNOWN_BLOCK_REASONS } from '../src/core/parsers/blockPage.js';
import { convertWikiLinks, parseInjectedNotes, wikiPageUrl } from '../src/core/parsers/notes.js';
import {
  acceptDownloadedCert,
  bundleCoverage,
  combinePem,
  isNetfreeName,
  matchStoreCerts,
  normalizeThumbprint,
  parseDn,
  splitPem,
} from '../src/core/parsers/certs.js';
import { ENTERPRISE_ROOTS_PREF, parsePrefs, parseProfilesIni, upsertUserPref } from '../src/core/parsers/firefox.js';
import { parsePsJson, parseStoreCerts, storeFromPsParentPath } from '../src/core/parsers/powershell.js';
import { isKeyUsageError, parsePipConfigList, parsePyLauncherList, parsePyProbe, parseWhere, versionGte } from '../src/core/parsers/python.js';
import { fixture, OFFICIAL, ROOT_ED25519_PEM, ROOT_RSA_PEM, ROOT_X2_RSA_PEM } from './helpers.js';

describe('block page parsing', () => {
  it('parses a real "unknown" block page (reddit)', () => {
    const b = parseBlockPage(fixture('block-unknown.html'));
    expect(b).not.toBeNull();
    expect(b!.reason).toBe('unknown');
    expect(b!.blockedUrl).toBe('https://www.reddit.com/');
    expect(b!.blockPageUrl.startsWith('https://netfree.link/block/#%7B')).toBe(true);
  });

  it('parses a real "special-site" block page (youtube)', () => {
    const b = parseBlockPage(fixture('block-special-site.html'));
    expect(b?.reason).toBe('special-site');
    expect(b?.blockedUrl).toBe('https://www.youtube.com/');
  });

  it('parses the risk-type example from an API endpoint', () => {
    const json = { block: 'risk-type', page_info: { url: 'https://api.openai.com/v1/responses' } };
    const body = `<iframe src="//netfree.link/block/#${encodeURIComponent(JSON.stringify(json))}"></iframe>`;
    const b = parseBlockPage(body);
    expect(b?.reason).toBe('risk-type');
    expect(b?.blockedUrl).toBe('https://api.openai.com/v1/responses');
    expect(b?.payload).toEqual(json);
  });

  it('handles HTML-entity-escaped fragments', () => {
    const body = `<iframe src="//netfree.link/block/#{&quot;block&quot;:&quot;deny&quot;}"></iframe>`;
    expect(parseBlockPage(body)?.reason).toBe('deny');
  });

  it('returns null for non-block pages and malformed JSON', () => {
    expect(parseBlockPage('<html>hello</html>')).toBeNull();
    expect(parseBlockPage('<iframe src="//netfree.link/block/#%7Bnot-json"></iframe>')).toBeNull();
  });

  it('detects blocks by status or iframe', () => {
    expect(looksLikeBlock(418, '')).toBe(true);
    expect(looksLikeBlock(200, fixture('block-unknown.html'))).toBe(true);
    expect(looksLikeBlock(200, '<html></html>')).toBe(false);
  });

  it('explains known reasons in Hebrew and keeps unknown ones raw', () => {
    for (const r of KNOWN_BLOCK_REASONS) {
      const e = explainBlockReason(r);
      expect(e.known).toBe(true);
      expect(e.he).toMatch(/[\u0590-\u05FF]/);
    }
    const u = explainBlockReason('some-new-reason');
    expect(u.known).toBe(false);
    expect(u.he).toContain('some-new-reason');
    expect(u.en).toContain('some-new-reason');
  });
});

describe('injected notes / wiki links', () => {
  it('converts [[Page|label]] and [[Page]] links', () => {
    const r = convertWikiLinks('See [[AI_Chats_in_NetFree|Click here to read more]] and [[Some Page]].');
    expect(r.text).toBe(
      'See Click here to read more (https://netfree.link/wiki/AI_Chats_in_NetFree) and Some Page (https://netfree.link/wiki/Some_Page).',
    );
    expect(r.links.map((l) => l.url)).toEqual(['https://netfree.link/wiki/AI_Chats_in_NetFree', 'https://netfree.link/wiki/Some_Page']);
  });

  it('percent-encodes Hebrew wiki page names', () => {
    expect(wikiPageUrl('צאט AI בנטפרי')).toBe(`https://netfree.link/wiki/${encodeURIComponent('צאט_AI_בנטפרי')}`);
  });

  it('extracts the real chatgpt.com note (jsondata attribute)', () => {
    const info = parseInjectedNotes(fixture('chatgpt-note.html'));
    expect(info.notes).toHaveLength(1);
    const n = info.notes[0]!;
    expect(n.en).toContain('Filter content that is known as personal or private');
    expect(n.en).toContain('(https://netfree.link/wiki/AI_Chats_in_NetFree)');
    expect(n.en).not.toContain('[[');
    expect(n.he).toMatch(/[\u0590-\u05FF]/);
    expect(n.links.some((l) => l.url === 'https://netfree.link/wiki/AI_Chats_in_NetFree')).toBe(true);
    expect(info.scripts).toEqual(['note-in-site.js', 'go-payment.js', 'popup-card-init.js']);
  });

  it('extracts notes from plain embedded JSON with escaped quotes', () => {
    const html =
      '<script>var x = {"noteSite":"שלום","noteSiteEn":"For images on this website to work you need to set \\"Filter content that is known as personal or private\\" [[AI_Chats_in_NetFree|more]]"};</script>' +
      '<script src="//netfree.link/injection-script/nisa.js"></script>';
    const info = parseInjectedNotes(html);
    expect(info.notes[0]?.en).toBe(
      'For images on this website to work you need to set "Filter content that is known as personal or private" more (https://netfree.link/wiki/AI_Chats_in_NetFree)',
    );
    expect(info.notes[0]?.he).toBe('שלום');
    expect(info.scripts).toEqual(['nisa.js']);
  });

  it('returns nothing for clean pages', () => {
    expect(parseInjectedNotes('<html><body>hi</body></html>')).toEqual({ notes: [], scripts: [] });
  });
});

describe('certificate helpers', () => {
  it('parses Windows-style DNs including quoted values with commas', () => {
    const dn = parseDn('CN="NetFree Sign , NetFreeAnywhere", OU=netfree.link, O=NetFree, L=Jerusalem, S=israel, C=IL');
    expect(dn.CN).toBe('NetFree Sign , NetFreeAnywhere');
    expect(dn.O).toBe('NetFree');
    expect(dn.C).toBe('IL');
    const dn2 = parseDn("CN=NetFree Root CA X2 1990-2200 RSA, OU=netfree.link, O=NetFree, S=Modi'in Ilit, C=IL");
    expect(dn2.CN).toBe('NetFree Root CA X2 1990-2200 RSA');
    expect(dn2.S).toBe("Modi'in Ilit");
  });

  it('parses Node-style (newline separated) DNs', () => {
    expect(parseDn('C=IL\nST=Modi\'in Ilit\nO=NetFree\nCN=NetFree Root CA 1990-2200 RSA').CN).toBe('NetFree Root CA 1990-2200 RSA');
  });

  it('recognizes Netfree names (the live intermediate issuer)', () => {
    expect(isNetfreeName({ O: 'NetFree WiFree3', CN: 'NetFree Node Intermediate CA, NetFree WiFree3' })).toBe(true);
    expect(isNetfreeName({ O: 'Google Trust Services', CN: 'WE2' })).toBe(false);
  });

  it('computes the official thumbprints', () => {
    expect(OFFICIAL[0]!.sha1).toBe('6337F278671D9207C03A74B9D818E5B80F225856');
    expect(OFFICIAL[0]!.subjectCN).toBe('NetFree Root CA X2 1990-2200 RSA');
    expect(OFFICIAL[1]!.sha1).toBe('1831EC6A8E9886841E3B6F26CD3A396F2B5C9B3B');
    expect(normalizeThumbprint('63:37:f2 78')).toBe('6337F278');
  });

  it('matches Windows store entries by thumbprint, then by subject', () => {
    const m = matchStoreCerts(
      [
        { store: 'CurrentUser\\Root', subject: 'CN=NetFree Root CA X2 1990-2200 RSA, O=NetFree', thumbprint: '6337F278671D9207C03A74B9D818E5B80F225856' },
        { store: 'LocalMachine\\Root', subject: 'CN=NetFree Root CA X2 1990-2200 RSA, O=NetFree', thumbprint: '6337F278671D9207C03A74B9D818E5B80F225856' },
        { store: 'CurrentUser\\Root', subject: 'CN=NetFree Root CA 1990-2200 RSA, O=NetFree', thumbprint: 'DEADBEEF' },
      ],
      OFFICIAL,
    );
    expect(m.present).toHaveLength(1);
    expect(m.present[0]!.stores).toEqual(['CurrentUser\\Root', 'LocalMachine\\Root']);
    expect(m.subjectOnly.map((s) => s.cert.name)).toEqual(['root_ca_rsa.crt']);
    expect(m.missing.map((s) => s.name)).toEqual(['root_ca_ed25519.crt']);
  });

  it('splits, combines (dedupes) and measures PEM bundles', () => {
    const combined = combinePem([ROOT_RSA_PEM, ROOT_X2_RSA_PEM, ROOT_RSA_PEM.replace(/\n/g, '\r\n')]);
    expect(splitPem(combined)).toHaveLength(2);
    const cov = bundleCoverage(combined, OFFICIAL);
    expect(cov.present).toHaveLength(2);
    expect(cov.missing).toEqual(['NetFree Root CA 1990-2200 ED25519']);
  });

  it('accepts only pinned Netfree roots from unverified downloads', () => {
    expect(acceptDownloadedCert(ROOT_RSA_PEM, false)).toBe(true);
    expect(acceptDownloadedCert(ROOT_ED25519_PEM, false)).toBe(true);
    expect(acceptDownloadedCert('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', true)).toBe(false);
    expect(acceptDownloadedCert('<html>404</html>', true)).toBe(false);
  });
});

describe('Firefox parsing', () => {
  const ini = `[Install308046B0AF4A39CB]
Default=Profiles/abc.default-release
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=Profiles/xyz.default
Default=1

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/abc.default-release

[Profile2]
Name=work
IsRelative=0
Path=D:\\ff\\work

[General]
StartWithLastProfile=1
Version=2
`;

  it('parses profiles.ini', () => {
    const p = parseProfilesIni(ini);
    expect(p.map((x) => x.name)).toEqual(['default', 'default-release', 'work']);
    expect(p[0]!.isDefault).toBe(true);
    expect(p[1]!.isDefault).toBe(true); // via [Install...] Default
    expect(p[2]).toMatchObject({ isRelative: false, path: 'D:\\ff\\work', isDefault: false });
  });

  it('parses prefs.js values of all types; later lines win', () => {
    const prefs = parsePrefs(`// Mozilla User Preferences
user_pref("app.update.lastUpdateTime", 1700000000);
user_pref("security.enterprise_roots.enabled", false);
user_pref("browser.startup.homepage", "https://example.com/\\"q\\"");
user_pref("security.enterprise_roots.enabled", true);
`);
    expect(prefs.get(ENTERPRISE_ROOTS_PREF)).toBe(true);
    expect(prefs.get('app.update.lastUpdateTime')).toBe(1700000000);
    expect(prefs.get('browser.startup.homepage')).toBe('https://example.com/"q"');
  });

  it('upserts a pref into user.js (replace, append, empty)', () => {
    expect(upsertUserPref('', ENTERPRISE_ROOTS_PREF, true)).toBe('// Added by netfree-doctor\nuser_pref("security.enterprise_roots.enabled", true);\n');
    const existing = 'user_pref("a.b", 1);\nuser_pref("security.enterprise_roots.enabled", false);\n';
    expect(upsertUserPref(existing, ENTERPRISE_ROOTS_PREF, true)).toBe('user_pref("a.b", 1);\nuser_pref("security.enterprise_roots.enabled", true);\n');
    expect(upsertUserPref('user_pref("a.b", 1);', ENTERPRISE_ROOTS_PREF, true)).toBe('user_pref("a.b", 1);\nuser_pref("security.enterprise_roots.enabled", true);\n');
    const crlf = 'user_pref("a.b", 1);\r\n';
    expect(upsertUserPref(crlf, ENTERPRISE_ROOTS_PREF, true)).toBe('user_pref("a.b", 1);\r\nuser_pref("security.enterprise_roots.enabled", true);\r\n');
  });
});

describe('PowerShell JSON parsing', () => {
  it('handles arrays, single objects, empty output and BOM', () => {
    expect(parsePsJson('')).toEqual([]);
    expect(parsePsJson('  \r\n')).toEqual([]);
    expect(parsePsJson('{"a":1}')).toEqual([{ a: 1 }]);
    expect(parsePsJson('\uFEFF[{"a":1},{"a":2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it('converts /Date(ms)/ values to ISO strings', () => {
    const [o] = parsePsJson('{"NotAfter":"\\/Date(7258118400000)\\/"}');
    expect(o!.NotAfter).toBe('2200-01-01T00:00:00.000Z');
  });

  it('parses real Get-ChildItem Cert: output', () => {
    const out = `[{"PSParentPath":"Microsoft.PowerShell.Security\\\\Certificate::CurrentUser\\\\Root","Subject":"CN=NetFree Root CA X2 1990-2200 RSA, OU=netfree.link, O=NetFree, S=Modi\\u0027in Ilit, C=IL","Thumbprint":"6337F278671D9207C03A74B9D818E5B80F225856","NotAfter":"\\/Date(7258118400000)\\/"}]`;
    const certs = parseStoreCerts(out);
    expect(certs).toEqual([
      {
        store: 'CurrentUser\\Root',
        subject: "CN=NetFree Root CA X2 1990-2200 RSA, OU=netfree.link, O=NetFree, S=Modi'in Ilit, C=IL",
        thumbprint: '6337F278671D9207C03A74B9D818E5B80F225856',
        notAfter: '2200-01-01T00:00:00.000Z',
      },
    ]);
    expect(storeFromPsParentPath('Microsoft.PowerShell.Security\\Certificate::LocalMachine\\Root')).toBe('LocalMachine\\Root');
  });
});

describe('Python parsing', () => {
  it('parses py -0p (new and old formats)', () => {
    const out = ` -V:3.14[-64] *   C:\\Users\\U\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe
 -V:3.12[-64]     C:\\Users\\U\\AppData\\Local\\Python\\pythoncore-3.12-64\\python.exe
 -3.9-64          C:\\Python39\\python.exe
`;
    const p = parsePyLauncherList(out);
    expect(p).toHaveLength(3);
    expect(p[0]).toMatchObject({ version: '3.14', isDefault: true });
    expect(p[1]).toMatchObject({ version: '3.12', isDefault: false });
    expect(p[2]).toMatchObject({ version: '3.9-64', path: 'C:\\Python39\\python.exe' });
  });

  it('parses where output and flags Store stubs', () => {
    const w = parseWhere('C:\\Users\\U\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe\r\nC:\\Python312\\python.exe\r\n');
    expect(w).toHaveLength(2);
    expect(parsePyLauncherList(' -V:3.12 *  C:\\Users\\U\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe')[0]?.isStoreStub).toBe(true);
  });

  it('parses pip config list (Python repr with doubled backslashes)', () => {
    const cfg = parsePipConfigList("global.cert='C:\\\\ProgramData\\\\NetFree\\\\CA\\\\bundle.crt'\nglobal.timeout='60'\n");
    expect(cfg['global.cert']).toBe('C:\\ProgramData\\NetFree\\CA\\bundle.crt');
    expect(cfg['global.timeout']).toBe('60');
  });

  it('parses the probe output and recognizes the key-usage error', () => {
    const p = parsePyProbe('noise\n{"version":"3.14.6","probe_system":"SSLCertVerificationError: CA cert does not include key usage extension"}\n');
    expect(p?.version).toBe('3.14.6');
    expect(isKeyUsageError(p?.probe_system)).toBe(true);
    expect(isKeyUsageError('unable to get local issuer certificate')).toBe(false);
    expect(parsePyProbe('Traceback...')).toBeNull();
  });

  it('compares versions', () => {
    expect(versionGte('24.2', '24.2')).toBe(true);
    expect(versionGte('26.1.2', '24.2')).toBe(true);
    expect(versionGte('3.9', '3.10')).toBe(false);
  });
});

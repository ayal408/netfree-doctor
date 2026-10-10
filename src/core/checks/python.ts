import type { Check, CheckResult, Ctx } from '../types.js';
import { FIXES } from '../fixes/catalog.js';
import {
  parsePipConfigList,
  parsePyLauncherList,
  parsePyProbe,
  parseWhere,
  isStoreStub,
  PY_PROBE,
  isKeyUsageError,
  type PyProbe,
} from '../parsers/python.js';
import { coverageOf, coverageWorks, joinPath, liveNetfreeRoot, readEnvVar, stripQuotes, wantedCerts } from './shared.js';

export function pythonBundlePath(ctx: Ctx): string {
  return joinPath(ctx, ctx.dataDir, 'python-ca-bundle.pem');
}

/** All Python interpreters found (real ones first; Store stubs dropped). */
export async function findPythons(ctx: Ctx): Promise<{ path: string; isDefault: boolean }[]> {
  const found = new Map<string, { path: string; isDefault: boolean }>();
  if (ctx.platform === 'win32') {
    const py = await ctx.exec('py', ['-0p'], 15000);
    if (!py.error && py.code === 0) {
      for (const p of parsePyLauncherList(py.stdout)) if (!p.isStoreStub) found.set(p.path.toLowerCase(), { path: p.path, isDefault: p.isDefault });
    }
    const where = await ctx.exec('where', ['python'], 15000);
    if (!where.error && where.code === 0) {
      for (const p of parseWhere(where.stdout)) {
        if (isStoreStub(p) || found.has(p.toLowerCase())) continue;
        found.set(p.toLowerCase(), { path: p, isDefault: false });
      }
    }
  } else {
    for (const name of ['python3', 'python']) {
      const w = await ctx.exec('which', [name], 5000);
      const p = w.stdout.trim().split('\n')[0];
      if (!w.error && w.code === 0 && p && !found.has(p)) found.set(p, { path: p, isDefault: found.size === 0 });
    }
  }
  return [...found.values()].sort((a, b) => Number(b.isDefault) - Number(a.isDefault));
}

export async function probePython(ctx: Ctx, exe: string): Promise<PyProbe | null> {
  const r = await ctx.exec(exe, ['-E', '-c', PY_PROBE], 60000);
  if (r.error) return null;
  return parsePyProbe(r.stdout);
}

export async function pipConfig(ctx: Ctx, exe: string): Promise<Record<string, string>> {
  const r = await ctx.exec(exe, ['-m', 'pip', 'config', 'list'], 30000);
  if (r.error || r.code !== 0) return {};
  return parsePipConfigList(r.stdout);
}

export const pythonCheck: Check = {
  id: 'python',
  titleHe: 'Python / pip',
  titleEn: 'Python / pip',
  async run(ctx): Promise<CheckResult> {
    const pythons = await findPythons(ctx);
    if (pythons.length === 0) {
      return { status: 'info', summaryHe: 'Python לא נמצא במחשב.', summaryEn: 'Python not found.' };
    }
    const main = pythons[0]!;
    const probe = await probePython(ctx, main.path);
    const live = await liveNetfreeRoot(ctx);
    const { official } = await wantedCerts(ctx);
    const liveW = live ? { sha1: live.sha1, subjectCN: live.subject.CN ?? '?' } : null;
    const detailsHe: string[] = [`נמצאו: ${pythons.map((p) => p.path).join(' ; ')}`];
    const detailsEn: string[] = [`Found: ${pythons.map((p) => p.path).join(' ; ')}`];
    detailsHe.push(`נבדק: ${main.path}${probe ? ` (Python ${probe.version}${probe.pip_version ? `, pip ${probe.pip_version}` : ''})` : ''}`);
    detailsEn.push(`Checked: ${main.path}${probe ? ` (Python ${probe.version}${probe.pip_version ? `, pip ${probe.pip_version}` : ''})` : ''}`);

    const fileCovers = async (p: string | undefined): Promise<boolean | null> => {
      if (!p) return null;
      const text = await ctx.readFile(stripQuotes(p));
      return text !== null && coverageWorks(coverageOf(text, liveW, official));
    };

    const cfg = probe?.has_pip ? await pipConfig(ctx, main.path) : {};
    const pipCert = cfg['global.cert'] ?? cfg['install.cert'];
    const pipCertOk = await fileCovers(pipCert);
    const envPip = await readEnvVar(ctx, 'PIP_CERT');
    const envPipOk = await fileCovers(envPip.effective);
    const reqBundle = await readEnvVar(ctx, 'REQUESTS_CA_BUNDLE');
    const reqOk = await fileCovers(reqBundle.effective);
    const sslCertFile = await readEnvVar(ctx, 'SSL_CERT_FILE');
    const sslOk = await fileCovers(sslCertFile.effective);

    const yesNo = (b: boolean | null, he: boolean) => (b === null ? (he ? 'לא מוגדר' : 'not set') : b ? (he ? 'מכיל את נטפרי ✔' : 'covers Netfree ✔') : he ? 'לא מכיל את נטפרי ✖' : 'missing Netfree ✖');
    detailsHe.push(`pip global.cert: ${pipCert ?? '—'} (${yesNo(pipCertOk, true)})`);
    detailsEn.push(`pip global.cert: ${pipCert ?? '—'} (${yesNo(pipCertOk, false)})`);
    detailsHe.push(`REQUESTS_CA_BUNDLE: ${reqBundle.effective ?? '—'} (${yesNo(reqOk, true)})`);
    detailsEn.push(`REQUESTS_CA_BUNDLE: ${reqBundle.effective ?? '—'} (${yesNo(reqOk, false)})`);
    detailsHe.push(`SSL_CERT_FILE: ${sslCertFile.effective ?? '—'} (${yesNo(sslOk, true)})`);
    detailsEn.push(`SSL_CERT_FILE: ${sslCertFile.effective ?? '—'} (${yesNo(sslOk, false)})`);
    if (envPip.effective) {
      detailsHe.push(`PIP_CERT: ${envPip.effective} (${yesNo(envPipOk, true)})`);
      detailsEn.push(`PIP_CERT: ${envPip.effective} (${yesNo(envPipOk, false)})`);
    }
    if (probe) {
      detailsHe.push(`חיבור ל-pypi.org עם certifi בלבד (כמו requests): ${probe.probe_certifi ?? 'certifi לא נמצא'}`);
      detailsEn.push(`pypi.org with certifi only (like requests): ${probe.probe_certifi ?? 'certifi not found'}`);
      detailsHe.push(`חיבור ל-pypi.org עם מאגר המערכת (ssl): ${probe.probe_system}`);
      detailsEn.push(`pypi.org with the system store (ssl): ${probe.probe_system}`);
      if (probe.probe_system_nonstrict) {
        detailsHe.push(`אותה בדיקה בלי VERIFY_X509_STRICT (לאבחון בלבד): ${probe.probe_system_nonstrict}`);
        detailsEn.push(`Same without VERIFY_X509_STRICT (diagnosis only): ${probe.probe_system_nonstrict}`);
      }
      detailsHe.push(`truststore מותקן: ${probe.truststore ? 'כן' : 'לא'}, pip-system-certs מותקן: ${probe.pip_system_certs ? 'כן' : 'לא'}`);
      detailsEn.push(`truststore installed: ${probe.truststore}, pip-system-certs installed: ${probe.pip_system_certs}`);
    }
    detailsHe.push(
      'חלופה מומלצת: pip install pip-system-certs (או truststore) גורם ל-pip/requests להשתמש במאגר התעודות של Windows. לעולם אל תשתמשו ב---trusted-host או verify=False.',
    );
    detailsEn.push(
      'Recommended alternative: pip install pip-system-certs (or truststore) makes pip/requests use the Windows store. Never use --trusted-host or verify=False.',
    );

    const data: Record<string, unknown> = { python: main.path, probe, pipCert: pipCert ?? null };
    if (!probe) {
      return { status: 'warn', summaryHe: `לא הצלחנו להריץ את ${main.path}.`, summaryEn: `Could not run ${main.path}.`, detailsHe, detailsEn, data };
    }
    if (probe.requests_installed) {
      detailsHe.push(`בדיקה אמיתית עם requests: ${probe.probe_requests ?? '?'}`);
      detailsEn.push(`Real test with requests: ${probe.probe_requests ?? '?'}`);
    }

    // Real pip test (pip itself decides which store to use: truststore / global.cert / certifi).
    let pipLive: boolean | null = null;
    let pipErr = '';
    if (probe.has_pip) {
      const r = await ctx.exec(main.path, ['-E', '-m', 'pip', 'index', 'versions', 'pip', '--disable-pip-version-check', '--retries', '0', '--timeout', '10'], 45000);
      pipLive = !r.error && r.code === 0;
      if (!pipLive) pipErr = (r.error ?? r.stderr.trim().split(/\r?\n/).filter(Boolean).slice(-1)[0] ?? '').slice(0, 240);
      detailsHe.push(`בדיקה אמיתית של pip (pip index versions pip): ${pipLive ? 'עובד ✔' : `נכשל ✖ ${pipErr}`}`);
      detailsEn.push(`Real pip test (pip index versions pip): ${pipLive ? 'works ✔' : `failed ✖ ${pipErr}`}`);
    }

    const requestsLive = probe.requests_installed ? probe.probe_requests === 'ok' : reqOk === true || probe.probe_certifi === 'ok';
    const keyUsage =
      isKeyUsageError(probe.probe_system) || isKeyUsageError(probe.probe_requests) || isKeyUsageError(pipErr) || isKeyUsageError(probe.probe_certifi);
    data.pipLive = pipLive;
    data.requestsLive = requestsLive;
    data.keyUsageIssue = keyUsage;

    const keyUsageHe = [
      `Python ${probe.version} מפעיל בדיקת X.509 מחמירה (VERIFY_X509_STRICT, מ-Python 3.13). תעודת השורש של נטפרי שבשימוש כרגע (${live?.subject.CN ?? 'NetFree Root CA 1990-2200 RSA'}) חסרה את ההרחבה Key Usage, ולכן Python דוחה אותה גם כשהיא מוגדרת נכון.`,
      'זו לא תקלה בהגדרות שלכם, ולכן הוספת התעודה לקובץ (REQUESTS_CA_BUNDLE / pip cert) לא תעזור.',
      'פתרון בטוח: להשתמש באימות של Windows במקום OpenSSL: pip install pip-system-certs (אמור לפתור את requests), או בקוד: import truststore; truststore.inject_into_ssl()',
      'אפשר גם לפנות לתמיכת נטפרי: תעודות X2 החדשות כוללות Key Usage.',
    ];
    const keyUsageEn = [
      `Python ${probe.version} enables strict X.509 checks (VERIFY_X509_STRICT, since 3.13). The Netfree root currently in use (${live?.subject.CN ?? 'NetFree Root CA 1990-2200 RSA'}) lacks the Key Usage extension, so Python rejects it even when configured correctly.`,
      'This is not a configuration mistake, so adding the CA to a bundle (REQUESTS_CA_BUNDLE / pip cert) does not help.',
      'Safe fix: verify with Windows instead of OpenSSL: pip install pip-system-certs (should fix requests), or in code: import truststore; truststore.inject_into_ssl()',
      'You can also contact Netfree support: the new X2 roots include Key Usage.',
    ];

    const certifiWorks = probe.probe_certifi === 'ok';
    if (!live && certifiWorks) {
      return { status: 'info', summaryHe: 'לא זוהה סינון של נטפרי; Python מתחבר כרגיל.', summaryEn: 'No Netfree interception; Python connects normally.', detailsHe, detailsEn, data };
    }
    if (pipLive === false) {
      return {
        status: 'fail',
        summaryHe: keyUsage
          ? 'pip נכשל: Python בגרסה הזו דוחה את תעודת השורש הנוכחית של נטפרי (חסרה בה הרחבת Key Usage).'
          : 'pip לא מכיר את תעודת נטפרי, ולכן pip install ייכשל עם CERTIFICATE_VERIFY_FAILED.',
        summaryEn: keyUsage
          ? 'pip fails: this Python rejects the current Netfree root (missing Key Usage extension).'
          : 'pip does not trust the Netfree CA, so pip install fails with CERTIFICATE_VERIFY_FAILED.',
        detailsHe: keyUsage ? [...detailsHe, ...keyUsageHe] : detailsHe,
        detailsEn: keyUsage ? [...detailsEn, ...keyUsageEn] : detailsEn,
        ...(keyUsage ? {} : { fix: FIXES.python }),
        data,
      };
    }
    if (!requestsLive) {
      if (keyUsage) {
        return {
          status: 'warn',
          summaryHe: 'pip עובד, אבל requests/urllib ב-Python הזה נכשלים מול נטפרי: Python 3.13+ דוחה את תעודת השורש הנוכחית של נטפרי (חסרה בה הרחבת Key Usage).',
          summaryEn: 'pip works, but requests/urllib fail: Python 3.13+ rejects the current Netfree root (missing Key Usage extension).',
          detailsHe: [...detailsHe, ...keyUsageHe],
          detailsEn: [...detailsEn, ...keyUsageEn],
          data,
        };
      }
      return {
        status: 'warn',
        summaryHe:
          'pip עובד, אבל ספריות כמו requests (שמשתמשות ב-certifi) ייכשלו מול נטפרי. אפשר להגדיר REQUESTS_CA_BUNDLE לקובץ משולב, או להתקין pip-system-certs.',
        summaryEn: 'pip works, but libraries like requests (using certifi) will fail. Set REQUESTS_CA_BUNDLE to a combined bundle or install pip-system-certs.',
        detailsHe: [...detailsHe, `לאחר הרצת "fix ${FIXES.python.id}" אפשר להפנות גם את REQUESTS_CA_BUNDLE לקובץ: ${pythonBundlePath(ctx)}`],
        detailsEn: [...detailsEn, `After "fix ${FIXES.python.id}" you can also point REQUESTS_CA_BUNDLE to: ${pythonBundlePath(ctx)}`],
        ...(pipCertOk ? {} : { fix: FIXES.python }),
        data,
      };
    }
    return { status: 'ok', summaryHe: 'Python ו-pip מצליחים להתחבר דרך נטפרי.', summaryEn: 'Python and pip connect fine through Netfree.', detailsHe, detailsEn, data };
  },
};

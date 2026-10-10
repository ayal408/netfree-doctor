import type { Check, CheckResult, Ctx } from '../types.js';
import { FIXES } from '../fixes/catalog.js';
import { coverageOf, coverageWorks, liveNetfreeRoot, stripQuotes, wantedCerts } from './shared.js';

export async function gitConfigGet(ctx: Ctx, key: string, scope?: '--global'): Promise<string | null> {
  const args = ['config', ...(scope ? [scope] : []), '--get', key];
  const r = await ctx.exec('git', args, 10000);
  if (r.error || r.code !== 0) return null;
  const v = r.stdout.trim();
  return v.length ? v : null;
}

export const gitCheck: Check = {
  id: 'git',
  titleHe: 'Git',
  titleEn: 'Git',
  async run(ctx): Promise<CheckResult> {
    const ver = await ctx.exec('git', ['--version'], 10000);
    if (ver.error || ver.code !== 0) return { status: 'info', summaryHe: 'Git לא נמצא במחשב.', summaryEn: 'Git not found.' };

    const backend = (await gitConfigGet(ctx, 'http.sslBackend'))?.toLowerCase() ?? null;
    const caInfo = await gitConfigGet(ctx, 'http.sslCAInfo');
    const sslVerify = (await gitConfigGet(ctx, 'http.sslVerify'))?.toLowerCase() ?? null;
    const detailsHe = [ver.stdout.trim(), `http.sslBackend = ${backend ?? '(ברירת מחדל: openssl)'}`, `http.sslCAInfo = ${caInfo ?? '—'}`];
    const detailsEn = [ver.stdout.trim(), `http.sslBackend = ${backend ?? '(default: openssl)'}`, `http.sslCAInfo = ${caInfo ?? '—'}`];
    const data: Record<string, unknown> = { backend, caInfo, sslVerify };

    if (sslVerify === 'false') {
      return {
        status: 'fail',
        summaryHe: 'ב-Git כובתה בדיקת האבטחה (http.sslVerify=false). זה "פתרון" מסוכן; הפתרון הנכון הוא schannel.',
        summaryEn: 'Git TLS verification is disabled (http.sslVerify=false). That is a dangerous "fix"; the right one is schannel.',
        detailsHe,
        detailsEn,
        fix: FIXES.git,
        data,
      };
    }
    if (backend === 'schannel') {
      return {
        status: 'ok',
        summaryHe: 'Git משתמש במאגר התעודות של Windows (schannel), ולכן מכיר את נטפרי.',
        summaryEn: 'Git uses the Windows certificate store (schannel), so it trusts Netfree.',
        detailsHe,
        detailsEn,
        data,
      };
    }
    const live = await liveNetfreeRoot(ctx);
    if (caInfo) {
      const { official } = await wantedCerts(ctx);
      const text = await ctx.readFile(stripQuotes(caInfo));
      const cov = text === null ? 'none' : coverageOf(text, live ? { sha1: live.sha1, subjectCN: live.subject.CN ?? '?' } : null, official);
      data.caInfoCoverage = cov;
      if (coverageWorks(cov)) {
        return {
          status: 'ok',
          summaryHe: 'Git מוגדר עם קובץ תעודות שכולל את נטפרי (http.sslCAInfo).',
          summaryEn: 'Git uses a CA file that includes Netfree (http.sslCAInfo).',
          detailsHe,
          detailsEn,
          data,
        };
      }
      if (live) {
        return {
          status: 'fail',
          summaryHe: `קובץ התעודות של Git (http.sslCAInfo) ${text === null ? 'לא קיים' : 'לא כולל את תעודת נטפרי'}, ולכן git clone/pull ייכשלו.`,
          summaryEn: `Git's CA file (http.sslCAInfo) ${text === null ? 'is missing' : 'lacks the Netfree root'}, so git clone/pull fail.`,
          detailsHe,
          detailsEn,
          fix: FIXES.git,
          data,
        };
      }
    }
    if (!live) {
      return { status: 'info', summaryHe: 'לא זוהה סינון של נטפרי; אין צורך בשינוי ב-Git.', summaryEn: 'No Netfree interception; Git needs no change.', detailsHe, detailsEn, data };
    }
    // OpenSSL backend with its bundled CA file: try a real request.
    const probe = await ctx.exec('git', ['ls-remote', '--heads', 'https://github.com/git/git.git', 'refs/heads/master'], 20000);
    if (!probe.error && probe.code === 0) {
      return {
        status: 'ok',
        summaryHe: 'Git מצליח להתחבר ל-GitHub דרך נטפרי.',
        summaryEn: 'Git connects to GitHub through Netfree.',
        detailsHe,
        detailsEn,
        data,
      };
    }
    return {
      status: 'fail',
      summaryHe: 'Git משתמש ב-OpenSSL עם קובץ תעודות משלו שלא כולל את נטפרי, ולכן clone/pull ייכשלו (SSL certificate problem).',
      summaryEn: 'Git uses OpenSSL with its own CA file that lacks Netfree, so clone/pull fail (SSL certificate problem).',
      detailsHe: [...detailsHe, probe.stderr.trim().split(/\r?\n/).slice(-1)[0] ?? ''],
      detailsEn: [...detailsEn, probe.stderr.trim().split(/\r?\n/).slice(-1)[0] ?? ''],
      fix: FIXES.git,
      data,
    };
  },
};

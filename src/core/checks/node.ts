import type { Check, CheckResult, Ctx } from '../types.js';
import { FIXES } from '../fixes/catalog.js';
import { coverageOf, coverageWorks, execNpm, liveNetfreeRoot, readEnvVar, stripQuotes, wantedCerts, type Coverage } from './shared.js';

const COVERAGE_HE: Record<Coverage, string> = {
  full: 'מכיל את כל תעודות השורש של נטפרי',
  'live-only': 'מכיל את תעודת השורש הפעילה של נטפרי (אבל לא את כל התעודות הרשמיות)',
  partial: 'מכיל חלק מתעודות נטפרי, אבל לא את התעודה הפעילה',
  none: 'לא מכיל תעודות של נטפרי',
};
const COVERAGE_EN: Record<Coverage, string> = {
  full: 'contains all Netfree root CAs',
  'live-only': 'contains the active Netfree root (but not all official roots)',
  partial: 'contains some Netfree certs, but not the active one',
  none: 'contains no Netfree certificates',
};

export interface NpmState {
  cafile: string | null;
  strictSsl: boolean | null;
}

export async function readNpmState(ctx: Ctx): Promise<NpmState | null> {
  const caf = await execNpm(ctx, ['config', 'get', 'cafile'], 20000);
  if (caf.error || caf.code !== 0) return null;
  const strict = await execNpm(ctx, ['config', 'get', 'strict-ssl'], 20000);
  const cafRaw = stripQuotes(caf.stdout.trim());
  const strictRaw = strict.stdout.trim();
  return {
    cafile: cafRaw && cafRaw !== 'null' && cafRaw !== 'undefined' ? cafRaw : null,
    strictSsl: strictRaw === 'false' ? false : strictRaw === 'true' ? true : null,
  };
}

export const nodeCheck: Check = {
  id: 'node',
  titleHe: 'Node.js / npm',
  titleEn: 'Node.js / npm',
  async run(ctx): Promise<CheckResult> {
    const live = await liveNetfreeRoot(ctx);
    const { official } = await wantedCerts(ctx);
    const liveW = live ? { sha1: live.sha1, subjectCN: live.subject.CN ?? '?' } : null;
    const extra = await readEnvVar(ctx, 'NODE_EXTRA_CA_CERTS');
    const nodeOptions = ctx.env.NODE_OPTIONS ?? '';
    const useSystemCa = /--use-system-ca\b/.test(nodeOptions);
    const npm = await readNpmState(ctx);
    const detailsHe: string[] = [];
    const detailsEn: string[] = [];
    let extraCoverage: Coverage | null = null;

    if (extra.effective) {
      const path = stripQuotes(extra.effective);
      const text = await ctx.readFile(path);
      if (text === null) {
        detailsHe.push(`NODE_EXTRA_CA_CERTS מצביע על קובץ שלא קיים: ${path}`);
        detailsEn.push(`NODE_EXTRA_CA_CERTS points to a missing file: ${path}`);
        extraCoverage = 'none';
      } else {
        extraCoverage = coverageOf(text, liveW, official);
        detailsHe.push(`NODE_EXTRA_CA_CERTS = ${path}: ${COVERAGE_HE[extraCoverage]}`);
        detailsEn.push(`NODE_EXTRA_CA_CERTS = ${path}: ${COVERAGE_EN[extraCoverage]}`);
      }
    } else {
      detailsHe.push('NODE_EXTRA_CA_CERTS לא מוגדר.');
      detailsEn.push('NODE_EXTRA_CA_CERTS is not set.');
    }
    if (useSystemCa) {
      detailsHe.push('NODE_OPTIONS כולל --use-system-ca (Node משתמש במאגר של Windows).');
      detailsEn.push('NODE_OPTIONS includes --use-system-ca (Node uses the OS store).');
    }

    let npmProblem = false;
    let npmDanger = false;
    if (npm === null) {
      detailsHe.push('npm לא נמצא.');
      detailsEn.push('npm not found.');
    } else {
      if (npm.strictSsl === false) {
        npmDanger = true;
        detailsHe.push('⚠ ב-npm מוגדר strict-ssl=false: בדיקת האבטחה כבויה! זה "תיקון" מסוכן שכדאי לבטל.');
        detailsEn.push('⚠ npm has strict-ssl=false: TLS verification is OFF! This is a dangerous "fix" and should be reverted.');
      }
      if (npm.cafile) {
        const text = await ctx.readFile(npm.cafile);
        const cov = text === null ? 'none' : coverageOf(text, liveW, official);
        if (!coverageWorks(cov)) npmProblem = true;
        detailsHe.push(`npm cafile = ${npm.cafile}: ${text === null ? 'הקובץ לא קיים' : COVERAGE_HE[cov]}`);
        detailsEn.push(`npm cafile = ${npm.cafile}: ${text === null ? 'file missing' : COVERAGE_EN[cov]}`);
        if (npmProblem) {
          detailsHe.push('כש-cafile מוגדר, npm משתמש רק בו, ולכן הוא חייב לכלול את תעודת נטפרי.');
          detailsEn.push('When cafile is set npm uses only that file, so it must include the Netfree root.');
        }
      } else {
        detailsHe.push('npm cafile לא מוגדר (npm ישתמש ב-NODE_EXTRA_CA_CERTS).');
        detailsEn.push('npm cafile is not set (npm will use NODE_EXTRA_CA_CERTS).');
      }
    }
    detailsHe.push('חלופה: ב-Node 22.15+ / 23.8+ אפשר להפעיל עם --use-system-ca כדי להשתמש במאגר התעודות של Windows.');
    detailsEn.push('Alternative: Node 22.15+/23.8+ supports --use-system-ca to use the OS certificate store.');

    const data = { NODE_EXTRA_CA_CERTS: extra.effective ?? null, coverage: extraCoverage, npm, useSystemCa };
    const nodeOk = useSystemCa || (extraCoverage !== null && coverageWorks(extraCoverage));

    if (!live && !nodeOk && !npmDanger) {
      return {
        status: 'info',
        summaryHe: 'לא זוהה סינון של נטפרי, ולכן אין צורך בהגדרת תעודות ל-Node כרגע.',
        summaryEn: 'No Netfree interception detected, so Node needs no CA configuration right now.',
        detailsHe,
        detailsEn,
        data,
      };
    }
    if (npmDanger) {
      return {
        status: 'fail',
        summaryHe: 'ב-npm כובתה בדיקת האבטחה (strict-ssl=false). התיקון הנכון הוא להגדיר את תעודת נטפרי ולהחזיר את הבדיקה.',
        summaryEn: 'npm TLS verification is disabled (strict-ssl=false). The right fix is to configure the Netfree CA and re-enable it.',
        detailsHe,
        detailsEn,
        fix: FIXES.node,
        data,
      };
    }
    if (!nodeOk) {
      return {
        status: 'fail',
        summaryHe:
          'Node/npm לא מכירים את תעודת נטפרי, ולכן npm install ותוכנות Node ייכשלו בשגיאות כמו UNABLE_TO_GET_ISSUER_CERT_LOCALLY / SELF_SIGNED_CERT_IN_CHAIN.',
        summaryEn: 'Node/npm do not trust the Netfree CA, so npm install and Node apps fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY / SELF_SIGNED_CERT_IN_CHAIN.',
        detailsHe,
        detailsEn,
        fix: FIXES.node,
        data,
      };
    }
    if (npmProblem) {
      return {
        status: 'warn',
        summaryHe: 'Node מוגדר נכון, אבל ה-cafile של npm לא כולל את תעודת נטפרי, ולכן npm עלול להיכשל.',
        summaryEn: 'Node is configured, but npm cafile lacks the Netfree root, so npm may fail.',
        detailsHe,
        detailsEn,
        fix: FIXES.node,
        data,
      };
    }
    return {
      status: 'ok',
      summaryHe: 'Node ו-npm מכירים את תעודת נטפרי.',
      summaryEn: 'Node and npm trust the Netfree CA.',
      detailsHe,
      detailsEn,
      data,
    };
  },
};

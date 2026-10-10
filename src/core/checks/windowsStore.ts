import type { Check, CheckResult } from '../types.js';
import { matchStoreCerts, normalizeThumbprint, NETFREE_INSTALL_GUIDE } from '../parsers/certs.js';
import { parseStoreCerts, STORE_QUERY_PS } from '../parsers/powershell.js';
import { liveNetfreeRoot, notWindows } from './shared.js';

export const windowsStoreCheck: Check = {
  id: 'windows-store',
  titleHe: 'תעודות נטפרי במאגר של Windows',
  titleEn: 'Netfree root CAs in the Windows certificate store',
  async run(ctx): Promise<CheckResult> {
    const nw = notWindows(ctx);
    if (nw) return nw;

    const ps = await ctx.exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', STORE_QUERY_PS], 30000);
    if (ps.error || (ps.code !== 0 && !ps.stdout.trim())) {
      return {
        status: 'warn',
        summaryHe: 'לא הצלחנו לקרוא את מאגר התעודות של Windows (PowerShell).',
        summaryEn: 'Could not read the Windows certificate store (PowerShell).',
        detailsHe: [ps.error ?? ps.stderr.trim()],
        detailsEn: [ps.error ?? ps.stderr.trim()],
      };
    }
    const store = parseStoreCerts(ps.stdout);
    const { certs: official, source, error } = await ctx.getNetfreeCerts();
    const live = await liveNetfreeRoot(ctx);
    const match = matchStoreCerts(store, official);
    const liveInStore = live ? store.some((s) => normalizeThumbprint(s.thumbprint) === live.sha1) : undefined;

    const detailsHe: string[] = [];
    const detailsEn: string[] = [];
    for (const p of match.present) {
      detailsHe.push(`✔ ${p.cert.subjectCN} (${p.stores.join(', ')})`);
      detailsEn.push(`✔ ${p.cert.subjectCN} (${p.stores.join(', ')})`);
    }
    for (const p of match.subjectOnly) {
      detailsHe.push(`≈ ${p.cert.subjectCN}: קיימת תעודה באותו שם אך עם טביעת אצבע שונה (${p.stores.join(', ')})`);
      detailsEn.push(`≈ ${p.cert.subjectCN}: same name but different thumbprint (${p.stores.join(', ')})`);
    }
    for (const m of match.missing) {
      detailsHe.push(`✖ חסרה: ${m.subjectCN}`);
      detailsEn.push(`✖ missing: ${m.subjectCN}`);
    }
    if (official.length === 0) {
      detailsHe.push(`לא הצלחנו להוריד את התעודות הרשמיות מ-netfree.link (${error ?? source}); נבדקה רק תעודת השורש הפעילה.`);
      detailsEn.push(`Could not download the official certificates from netfree.link (${error ?? source}); only the live root was checked.`);
    }
    const guideHe = `מדריך ההתקנה הרשמי: ${NETFREE_INSTALL_GUIDE}`;
    const guideEn = `Official install guide: ${NETFREE_INSTALL_GUIDE}`;
    const data = {
      storeCerts: store.length,
      present: match.present.map((p) => p.cert.name),
      missing: match.missing.map((m) => m.name),
      liveRoot: live?.subject.CN ?? null,
      liveRootInStore: liveInStore ?? null,
    };

    if (liveInStore === false || (live === null && match.present.length === 0)) {
      return {
        status: 'fail',
        summaryHe:
          'תעודת השורש של נטפרי אינה מותקנת ב-Windows. דפדפנים ותוכנות יציגו שגיאות אבטחה ("החיבור אינו פרטי") באתרים מוצפנים.',
        summaryEn: 'The Netfree root CA is not installed in Windows. Browsers and apps will show security errors on HTTPS sites.',
        detailsHe: [...detailsHe, 'התקנת תעודת שורש היא פעולה רגישה, ולכן הכלי לא עושה אותה בעצמו. יש להתקין לפי המדריך של נטפרי.', guideHe],
        detailsEn: [...detailsEn, 'Installing a root CA is sensitive, so this tool does not do it. Follow the Netfree guide.', guideEn],
        data,
      };
    }
    if (match.missing.length > 0 || match.subjectOnly.length > 0) {
      return {
        status: 'warn',
        summaryHe: `תעודת השורש הפעילה מותקנת, אבל ${match.missing.length + match.subjectOnly.length} מתוך ${official.length} תעודות השורש הרשמיות חסרות. כדאי להשלים כדי שדברים לא יישברו כשנטפרי תעבור לתעודה אחרת.`,
        summaryEn: `The active root is installed, but ${match.missing.length + match.subjectOnly.length} of ${official.length} official roots are missing. Install them so nothing breaks when Netfree rotates certificates.`,
        detailsHe: [...detailsHe, guideHe],
        detailsEn: [...detailsEn, guideEn],
        data,
      };
    }
    return {
      status: 'ok',
      summaryHe: `כל תעודות השורש של נטפרי מותקנות ב-Windows (${match.present.length}).`,
      summaryEn: `All Netfree root CAs are installed in Windows (${match.present.length}).`,
      detailsHe,
      detailsEn,
      data,
    };
  },
};

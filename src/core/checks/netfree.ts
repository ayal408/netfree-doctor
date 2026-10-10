import type { Check, CheckResult, TlsProbeResult } from '../types.js';
import { findNetfreeInChain, isNetfreeName } from '../parsers/certs.js';
import { PROBE_HOSTS } from './shared.js';

function issuerLabel(r: TlsProbeResult): string {
  const leaf = r.chain[0];
  if (!leaf) return '?';
  const i = leaf.issuer;
  return [i.O ? `O=${i.O}` : '', i.CN ? `CN=${i.CN}` : ''].filter(Boolean).join(', ') || '?';
}

export const netfreeCheck: Check = {
  id: 'netfree',
  titleHe: 'האם החיבור עובר דרך נטפרי?',
  titleEn: 'Are you on Netfree?',
  async run(ctx): Promise<CheckResult> {
    const results = await Promise.all(PROBE_HOSTS.map(async (h) => ({ host: h, r: await ctx.tlsProbe(h, 443) })));
    const reachable = results.filter((x) => x.r.ok && x.r.chain.length > 0);
    const intercepted = reachable.filter((x) => findNetfreeInChain(x.r.chain) >= 0);
    const detailsHe: string[] = [];
    const detailsEn: string[] = [];
    for (const { host, r } of results) {
      if (!r.ok) {
        detailsHe.push(`${host}: אין חיבור (${r.error ?? 'שגיאה'})`);
        detailsEn.push(`${host}: no connection (${r.error ?? 'error'})`);
      } else {
        detailsHe.push(`${host}: מנפיק התעודה ${issuerLabel(r)}`);
        detailsEn.push(`${host}: certificate issuer ${issuerLabel(r)}`);
      }
    }

    if (reachable.length === 0) {
      return {
        status: 'fail',
        summaryHe: 'לא הצלחנו להתחבר לאף אתר בדיקה ב-HTTPS. בדקו שיש חיבור לאינטרנט.',
        summaryEn: 'Could not connect to any test site over HTTPS. Check your internet connection.',
        detailsHe,
        detailsEn,
        data: { onNetfree: null },
      };
    }

    if (intercepted.length === 0) {
      return {
        status: 'info',
        summaryHe: 'לא זוהה סינון של נטפרי בחיבור הזה (התעודות מקוריות). שאר הבדיקות עדיין יכולות לעזור.',
        summaryEn: 'No Netfree interception detected on this connection (original certificates).',
        detailsHe,
        detailsEn,
        data: { onNetfree: false },
      };
    }

    const sample = intercepted[0]!.r;
    const root = sample.chain[sample.chain.length - 1];
    const rootCN = root && isNetfreeName(root.issuer) ? root.issuer.CN ?? root.subject.CN : undefined;
    if (rootCN) {
      detailsHe.push(`תעודת השורש של השרשרת: ${rootCN}`);
      detailsEn.push(`Chain root certificate: ${rootCN}`);
    }
    const partial = intercepted.length < reachable.length;
    return {
      status: 'ok',
      summaryHe: partial
        ? `החיבור עובר דרך נטפרי (${intercepted.length} מתוך ${reachable.length} אתרי בדיקה מסוננים).`
        : 'החיבור עובר דרך נטפרי: התעבורה המוצפנת נבדקת עם תעודה של נטפרי, כצפוי.',
      summaryEn: partial
        ? `You are on Netfree (${intercepted.length} of ${reachable.length} test sites intercepted).`
        : 'You are on Netfree: HTTPS traffic is inspected with a Netfree certificate, as expected.',
      detailsHe,
      detailsEn,
      data: { onNetfree: true, root: rootCN ?? null, rootSha1: root?.sha1 ?? null },
    };
  },
};

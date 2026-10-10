import type { CheckOutcome, Status } from '../core/types.js';
import type { UrlDiagnosis } from '../core/urlCheck.js';

export type Lang = 'he' | 'en';

export interface FormatOptions {
  lang: Lang;
  color: boolean;
  verbose: boolean;
}

const ICON: Record<Status, string> = { ok: '✔', warn: '⚠', fail: '✖', info: 'ℹ' };
const COLOR: Record<Status, string> = { ok: '32', warn: '33', fail: '31', info: '36' };

export function paint(s: string, code: string, on: boolean): string {
  return on ? `\x1b[${code}m${s}\x1b[0m` : s;
}

export const T = {
  he: {
    header: 'netfree-doctor: אבחון בעיות "לא עובד בנטפרי"',
    fixAvailable: 'תיקון זמין',
    summary: (c: Record<Status, number>) => `סיכום: ${c.ok} תקין, ${c.warn} אזהרות, ${c.fail} תקלות, ${c.info} לידיעה`,
    fixHint: 'להצגת מה התיקון יעשה (בלי לבצע): netfree-doctor fix <מזהה> --dry-run',
    noBypass: 'הכלי עוזר לדברים לעבוד *עם* נטפרי. הוא לא עוקף את הסינון ולא מכבה בדיקות אבטחה.',
    urlHeader: (u: string) => `בדיקת כתובת: ${u}`,
    blockReason: 'סיבת החסימה',
    links: 'קישורים',
  },
  en: {
    header: 'netfree-doctor: diagnosing "doesn\'t work on Netfree" problems',
    fixAvailable: 'Fix available',
    summary: (c: Record<Status, number>) => `Summary: ${c.ok} ok, ${c.warn} warnings, ${c.fail} failures, ${c.info} info`,
    fixHint: 'To see what a fix would do (without doing it): netfree-doctor fix <id> --dry-run',
    noBypass: 'This tool helps things work *with* Netfree. It never bypasses the filter or disables security checks.',
    urlHeader: (u: string) => `Checking URL: ${u}`,
    blockReason: 'Block reason',
    links: 'Links',
  },
} as const;

export function countStatuses(results: { status: Status }[]): Record<Status, number> {
  const c: Record<Status, number> = { ok: 0, warn: 0, fail: 0, info: 0 };
  for (const r of results) c[r.status]++;
  return c;
}

export function formatOutcome(o: CheckOutcome, opt: FormatOptions): string[] {
  const he = opt.lang === 'he';
  const lines: string[] = [];
  const title = he ? o.titleHe : o.titleEn;
  lines.push(`${paint(ICON[o.status], COLOR[o.status], opt.color)} ${paint(title, '1', opt.color)}`);
  lines.push(`   ${he ? o.summaryHe : o.summaryEn}`);
  const details = he ? o.detailsHe : o.detailsEn;
  if (details?.length && (opt.verbose || o.status !== 'ok')) {
    for (const d of details) lines.push(paint(`     · ${d}`, '2', opt.color));
  }
  if (o.fix) {
    const t = T[opt.lang];
    lines.push(`   → ${t.fixAvailable}: ${he ? o.fix.titleHe : o.fix.titleEn}`);
    lines.push(`     netfree-doctor fix ${o.fix.id}`);
  }
  return lines;
}

export function formatReport(results: CheckOutcome[], opt: FormatOptions): string {
  const t = T[opt.lang];
  const lines: string[] = [paint(t.header, '1', opt.color), ''];
  for (const r of results) {
    lines.push(...formatOutcome(r, opt), '');
  }
  lines.push(t.summary(countStatuses(results)));
  if (results.some((r) => r.fix)) lines.push(t.fixHint);
  lines.push(paint(t.noBypass, '2', opt.color));
  return lines.join('\n');
}

export function formatDiagnosis(d: UrlDiagnosis, opt: FormatOptions): string {
  const t = T[opt.lang];
  const he = opt.lang === 'he';
  const lines: string[] = [paint(t.urlHeader(d.url), '1', opt.color), ''];
  for (const s of d.steps) lines.push(...formatOutcome(s, { ...opt, verbose: true }));
  lines.push('');
  lines.push(`${paint(ICON[d.status], COLOR[d.status], opt.color)} ${paint(he ? d.summaryHe : d.summaryEn, '1', opt.color)}`);
  if (d.block) {
    lines.push(`   ${t.blockReason}: ${d.block.reason}${d.block.explanation.known ? '' : ' (?)'}`);
    lines.push(`   ${he ? d.block.explanation.he : d.block.explanation.en}`);
  }
  const links = d.injection?.notes.flatMap((n) => n.links) ?? [];
  if (links.length) {
    lines.push(`   ${t.links}:`);
    for (const l of new Map(links.map((x) => [x.url, x])).values()) lines.push(`     ${l.label}: ${l.url}`);
  }
  return lines.join('\n');
}

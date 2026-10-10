#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { readFileSync } from 'node:fs';
import {
  ALL_CHECKS,
  applyPlan,
  describePlan,
  diagnoseUrl,
  FIX_DEFINITIONS,
  findFix,
  loadJournal,
  runChecks,
  undoTransaction,
  UnsafePlanError,
  validatePlanSafety,
} from '../core/index.js';
import { createNodeCtx } from '../platform/nodeCtx.js';
import { createFixIo } from '../platform/fixIo.js';
import { formatDiagnosis, formatReport, type Lang } from './format.js';

function version(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

const HELP_HE = `netfree-doctor - אבחון ותיקון בטוח של בעיות "לא עובד בנטפרי"

שימוש:
  netfree-doctor                 הרצת כל הבדיקות
  netfree-doctor check <url>     בדיקת כתובת אחת (DNS, TCP, TLS, HTTP, חסימה, הערות). תומך גם ב-wss://
  netfree-doctor fix             רשימת התיקונים הזמינים
  netfree-doctor fix <id>        הצגת התיקון ואישור לפני ביצוע
  netfree-doctor undo [id]       ביטול התיקון האחרון (או לפי מזהה) מתוך היומן והגיבויים
  netfree-doctor undo --list     הצגת יומן התיקונים

אפשרויות:
  --en          פלט באנגלית
  --json        פלט JSON
  --dry-run     (עם fix) רק להציג מה ייעשה, בלי לבצע
  --yes, -y     לבצע בלי לשאול
  --only a,b    להריץ רק את הבדיקות האלה (${ALL_CHECKS.map((c) => c.id).join(', ')})
  --verbose, -v להציג פרטים גם לבדיקות תקינות
  --no-color    בלי צבעים
`;

const HELP_EN = `netfree-doctor - diagnose and safely fix "doesn't work on Netfree" problems

Usage:
  netfree-doctor                 run all checks
  netfree-doctor check <url>     diagnose one URL (DNS, TCP, TLS, HTTP, block page, notes); wss:// supported
  netfree-doctor fix             list available fixes
  netfree-doctor fix <id>        show a fix and confirm before applying
  netfree-doctor undo [id]       revert the last fix (or a given one) from the journal/backups
  netfree-doctor undo --list     show the fix journal

Options:
  --en, --json, --dry-run, --yes/-y, --only a,b, --verbose/-v, --no-color
`;

async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const a = (await rl.question(question)).trim().toLowerCase();
    return ['y', 'yes', 'כ', 'כן'].includes(a);
  } finally {
    rl.close();
  }
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      en: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      yes: { type: 'boolean', short: 'y', default: false },
      'dry-run': { type: 'boolean', default: false },
      only: { type: 'string' },
      verbose: { type: 'boolean', short: 'v', default: false },
      'no-color': { type: 'boolean', default: false },
      list: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', default: false },
    },
  });
  const lang: Lang = values.en ? 'en' : 'he';
  const he = lang === 'he';
  const color = !values['no-color'] && !values.json && !!process.stdout.isTTY && !process.env.NO_COLOR;
  const fmt = { lang, color, verbose: values.verbose };
  const out = (s: string) => process.stdout.write(s + '\n');
  const [cmd = 'run', arg] = positionals;

  if (values.help || cmd === 'help') {
    out(he ? HELP_HE : HELP_EN);
    return 0;
  }
  if (values.version) {
    out(version());
    return 0;
  }

  const ctx = createNodeCtx();

  if (cmd === 'run') {
    const only = values.only?.split(',').map((s) => s.trim()).filter(Boolean);
    const checks = only ? ALL_CHECKS.filter((c) => only.includes(c.id)) : ALL_CHECKS;
    if (!values.json && process.stderr.isTTY) process.stderr.write(he ? 'מריץ בדיקות...\n' : 'Running checks...\n');
    const results = await runChecks(ctx, checks);
    if (values.json) out(JSON.stringify({ tool: 'netfree-doctor', version: version(), platform: ctx.platform, results }, null, 2));
    else out(formatReport(results, fmt));
    return results.some((r) => r.status === 'fail') ? 2 : 0;
  }

  if (cmd === 'check') {
    if (!arg) {
      out(he ? 'חסרה כתובת. דוגמה: netfree-doctor check https://chatgpt.com' : 'Missing URL. Example: netfree-doctor check https://chatgpt.com');
      return 1;
    }
    const d = await diagnoseUrl(ctx, arg);
    out(values.json ? JSON.stringify(d, null, 2) : formatDiagnosis(d, fmt));
    return d.status === 'fail' ? 2 : 0;
  }

  if (cmd === 'fix') {
    if (!arg) {
      if (values.json) out(JSON.stringify(FIX_DEFINITIONS.map(({ id, titleHe, titleEn }) => ({ id, titleHe, titleEn })), null, 2));
      else for (const f of FIX_DEFINITIONS) out(`  ${f.id.padEnd(26)} ${he ? f.titleHe : f.titleEn}`);
      return 0;
    }
    const def = findFix(arg);
    if (!def) {
      out(he ? `תיקון לא מוכר: ${arg}. הרשימה: netfree-doctor fix` : `Unknown fix: ${arg}. List: netfree-doctor fix`);
      return 1;
    }
    const plan = await def.plan(ctx);
    const violations = validatePlanSafety(plan, ctx.homeDir);
    if (values.json) {
      out(JSON.stringify({ fix: def.id, ops: plan.ops.map((o) => ({ ...o, ...(o.kind === 'writeFile' ? { content: `<${o.content.length} chars>` } : {}) })), blocker: plan.blockerEn ?? null, violations }, null, 2));
      if (values['dry-run']) return 0;
    } else {
      out(`${he ? 'תיקון' : 'Fix'}: ${he ? def.titleHe : def.titleEn} (${def.id})`);
      const note = he ? def.noteHe : def.noteEn;
      if (note) out(`! ${note}`);
      out(he ? 'מה ייעשה (dry-run):' : 'What will happen (dry-run):');
      for (const l of describePlan(plan, lang)) out(`  ${l}`);
    }
    if (violations.length) {
      out(he ? `התיקון נדחה מטעמי בטיחות: ${violations.map((v) => v.whyHe).join('; ')}` : `Refused for safety: ${violations.map((v) => v.whyEn).join('; ')}`);
      return 1;
    }
    if (plan.blockerHe) {
      out(he ? `לא ניתן לבצע כעת: ${plan.blockerHe}` : `Cannot apply now: ${plan.blockerEn}`);
      return 1;
    }
    if (values['dry-run']) {
      out(he ? '(dry-run: לא בוצע שום שינוי)' : '(dry-run: nothing was changed)');
      return 0;
    }
    if (!values.yes) {
      const ok = await confirm(he ? 'לבצע את התיקון? כל קובץ יגובה לפני שינוי, ואפשר לבטל עם "netfree-doctor undo". [כ/ל] ' : 'Apply this fix? Files are backed up first; revert with "netfree-doctor undo". [y/N] ');
      if (!ok) {
        out(he ? 'בוטל. לא בוצע שום שינוי.' : 'Cancelled. Nothing was changed.');
        return 1;
      }
    }
    try {
      const tx = await applyPlan(createFixIo(), ctx.dataDir, ctx.homeDir, plan);
      out(he ? `✔ התיקון בוצע (מזהה ביטול: ${tx.id}). לביטול: netfree-doctor undo ${tx.id}` : `✔ Applied (undo id: ${tx.id}). To revert: netfree-doctor undo ${tx.id}`);
      return 0;
    } catch (e) {
      if (e instanceof UnsafePlanError) out(he ? 'התיקון נדחה מטעמי בטיחות.' : 'Refused for safety.');
      out(`✖ ${e instanceof Error ? e.message : String(e)}`);
      out(he ? 'שלבים שבוצעו נרשמו ביומן; אפשר לבטל עם netfree-doctor undo' : 'Completed steps were journaled; revert with netfree-doctor undo');
      return 1;
    }
  }

  if (cmd === 'undo') {
    const io = createFixIo();
    const journal = await loadJournal(io, ctx.dataDir);
    if (values.list || values.json) {
      if (values.json) out(JSON.stringify(journal, null, 2));
      else if (journal.transactions.length === 0) out(he ? 'היומן ריק.' : 'Journal is empty.');
      else
        for (const t of journal.transactions)
          out(`${t.id}  ${t.fixId.padEnd(26)} ${t.undoneAt ? (he ? `(בוטל ${t.undoneAt})` : `(undone ${t.undoneAt})`) : he ? '(פעיל)' : '(active)'}${t.error ? ` ✖ ${t.error}` : ''}`);
      return 0;
    }
    const pending = journal.transactions.filter((t) => !t.undoneAt);
    const tx = arg ? pending.find((t) => t.id === arg) : pending[pending.length - 1];
    if (!tx) {
      out(he ? 'אין תיקון לבטל.' : 'Nothing to undo.');
      return 1;
    }
    out(he ? `ביטול תיקון ${tx.fixId} (${tx.id}):` : `Undo ${tx.fixId} (${tx.id}):`);
    for (const s of [...tx.steps].reverse()) {
      if (s.kind === 'file') out(`  - ${s.backup ? (he ? `שחזור ${s.path} מהגיבוי` : `restore ${s.path} from backup`) : he ? `מחיקת ${s.path} (לא היה קיים לפני)` : `delete ${s.path} (did not exist before)`}`);
      else if (s.undo) out(`  - $ ${[s.undo.file, ...s.undo.args].join(' ')}`);
    }
    if (values['dry-run']) return 0;
    if (!values.yes && !(await confirm(he ? 'לבצע? [כ/ל] ' : 'Proceed? [y/N] '))) {
      out(he ? 'בוטל.' : 'Cancelled.');
      return 1;
    }
    const r = await undoTransaction(io, ctx.dataDir, tx.id);
    if (r?.errors.length) {
      for (const e of r.errors) out(`✖ ${e}`);
      return 1;
    }
    out(he ? '✔ בוטל בהצלחה.' : '✔ Reverted.');
    return 0;
  }

  out(he ? HELP_HE : HELP_EN);
  return 1;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`netfree-doctor: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
    process.exitCode = 1;
  },
);

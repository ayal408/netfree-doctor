import type { ExecResult, FixOp } from '../types.js';
import type { FixPlan } from './definitions.js';

/** Side effects needed to apply/undo fixes (injected so the executor is testable). */
export interface FixIo {
  readFile(path: string): Promise<string | null>;
  writeFile(path: string, content: string): Promise<void>;
  copyFile(src: string, dst: string): Promise<void>;
  removeFile(path: string): Promise<void>;
  fileExists(path: string): Promise<boolean>;
  mkdirp(dir: string): Promise<void>;
  exec(file: string, args: string[]): Promise<ExecResult>;
  now(): Date;
  join(...parts: string[]): string;
  basename(path: string): string;
  dirname(path: string): string;
}

export type JournalStep =
  | { kind: 'file'; path: string; backup: string | null; description: string }
  | { kind: 'exec'; description: string; undo: { file: string; args: string[] } | null; backups: { path: string; backup: string }[] };

export interface Transaction {
  id: string;
  fixId: string;
  appliedAt: string;
  undoneAt?: string;
  steps: JournalStep[];
  /** Set when the transaction stopped half way. */
  error?: string;
}

export interface Journal {
  version: 1;
  transactions: Transaction[];
}

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

/**
 * Patterns a fix must never contain. These are the classic "solutions" that make things work by
 * turning security off - exactly what this tool refuses to do.
 */
export const FORBIDDEN_PATTERNS: { re: RegExp; whyHe: string; whyEn: string }[] = [
  { re: /NODE_TLS_REJECT_UNAUTHORIZED/i, whyHe: 'מכבה בדיקת תעודות ב-Node', whyEn: 'disables certificate checks in Node' },
  { re: /\bsslVerify\b\s*=?\s*false\b/i, whyHe: 'מכבה בדיקת תעודות ב-Git', whyEn: 'disables certificate checks in Git' },
  { re: /strict-ssl\s+(set\s+)?false|strict-ssl=false|set\s+strict-ssl\s+false/i, whyHe: 'מכבה בדיקת תעודות ב-npm', whyEn: 'disables certificate checks in npm' },
  { re: /--trusted-host|trusted-host\s*=/i, whyHe: 'מדלג על אימות תעודות ב-pip', whyEn: 'skips certificate checks in pip' },
  { re: /verify\s*=\s*False|PYTHONHTTPSVERIFY\s*=?\s*0/i, whyHe: 'מכבה אימות תעודות ב-Python', whyEn: 'disables certificate checks in Python' },
  { re: /--insecure|(^|\s)-k(\s|$)|--no-check-certificate/i, whyHe: 'מדלג על אימות תעודות', whyEn: 'skips certificate verification' },
  { re: /\b(vpn|proxy|socks5?|tor)\b/i, whyHe: 'עקיפת הסינון אסורה', whyEn: 'bypassing the filter is not allowed' },
];

export interface SafetyViolation {
  op: number;
  whyHe: string;
  whyEn: string;
}

function opText(op: FixOp): string {
  return op.kind === 'exec' ? [op.file, ...op.args].join(' ') : `${op.path}\n${op.content}`;
}

/**
 * Validates a plan: no forbidden patterns, and files are written only inside the user's own
 * profile (`allowedRoot`, normally %USERPROFILE%).
 */
export function validatePlanSafety(plan: FixPlan, allowedRoot: string): SafetyViolation[] {
  const out: SafetyViolation[] = [];
  const root = allowedRoot.replace(/[\\/]+$/, '').toLowerCase();
  plan.ops.forEach((op, i) => {
    const text = opText(op);
    for (const f of FORBIDDEN_PATTERNS) {
      // Certificates are base64; only check the non-PEM part of file contents.
      const scan = op.kind === 'writeFile' ? text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '') : text;
      if (f.re.test(scan)) out.push({ op: i, whyHe: f.whyHe, whyEn: f.whyEn });
    }
    if (op.kind === 'writeFile') {
      const p = op.path.toLowerCase();
      if (!(p.startsWith(root + '\\') || p.startsWith(root + '/'))) {
        out.push({ op: i, whyHe: `כתיבה מחוץ לתיקיית המשתמש: ${op.path}`, whyEn: `write outside the user profile: ${op.path}` });
      }
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Dry-run description
// ---------------------------------------------------------------------------

export function describePlan(plan: FixPlan, lang: 'he' | 'en'): string[] {
  const he = lang === 'he';
  const lines: string[] = [];
  plan.ops.forEach((op, i) => {
    lines.push(`${i + 1}. ${he ? op.descriptionHe : op.descriptionEn}`);
    if (op.kind === 'writeFile') {
      lines.push(he ? '   (אם הקובץ קיים, יישמר עותק גיבוי לפני השינוי)' : '   (an existing file is backed up first)');
    } else {
      lines.push(`   $ ${[op.file, ...op.args.map((a) => (/\s/.test(a) ? `"${a}"` : a))].join(' ')}`);
      if (op.undo) lines.push(`   ${he ? 'ביטול' : 'undo'}: ${[op.undo.file, ...op.undo.args].join(' ')}`);
    }
  });
  for (const n of he ? plan.notesHe : plan.notesEn) lines.push(`• ${n}`);
  return lines;
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

export async function loadJournal(io: FixIo, dataDir: string): Promise<Journal> {
  const text = await io.readFile(io.join(dataDir, 'journal.json'));
  if (!text) return { version: 1, transactions: [] };
  try {
    const j = JSON.parse(text) as Journal;
    if (j && Array.isArray(j.transactions)) return j;
  } catch {
    /* fall through */
  }
  return { version: 1, transactions: [] };
}

async function saveJournal(io: FixIo, dataDir: string, j: Journal): Promise<void> {
  await io.mkdirp(dataDir);
  await io.writeFile(io.join(dataDir, 'journal.json'), JSON.stringify(j, null, 2));
}

function txId(d: Date): string {
  return d.toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '-');
}

// ---------------------------------------------------------------------------
// Apply / undo
// ---------------------------------------------------------------------------

export class UnsafePlanError extends Error {
  constructor(public readonly violations: SafetyViolation[]) {
    super(`Refusing to apply an unsafe fix: ${violations.map((v) => v.whyEn).join('; ')}`);
  }
}

/**
 * Applies a plan: backs up every file before touching it, records each step in the journal
 * (so `undo` can revert), and stops at the first failing step.
 */
export async function applyPlan(io: FixIo, dataDir: string, allowedRoot: string, plan: FixPlan): Promise<Transaction> {
  const violations = validatePlanSafety(plan, allowedRoot);
  if (violations.length) throw new UnsafePlanError(violations);
  if (plan.blockerEn) throw new Error(plan.blockerEn);

  const journal = await loadJournal(io, dataDir);
  const now = io.now();
  let id = txId(now);
  let n = 1;
  while (journal.transactions.some((t) => t.id === id)) id = `${txId(now)}-${++n}`;
  const backupDir = io.join(dataDir, 'backups', id);
  const tx: Transaction = { id, fixId: plan.fix.id, appliedAt: now.toISOString(), steps: [] };
  journal.transactions.push(tx);
  let counter = 0;

  const backup = async (path: string): Promise<string | null> => {
    if (!(await io.fileExists(path))) return null;
    await io.mkdirp(backupDir);
    const dst = io.join(backupDir, `${++counter}-${io.basename(path)}`);
    await io.copyFile(path, dst);
    return dst;
  };

  try {
    for (const op of plan.ops) {
      if (op.kind === 'writeFile') {
        const b = await backup(op.path);
        await io.mkdirp(io.dirname(op.path));
        await io.writeFile(op.path, op.content);
        tx.steps.push({ kind: 'file', path: op.path, backup: b, description: op.descriptionEn });
      } else {
        const backups: { path: string; backup: string }[] = [];
        for (const p of op.backupPaths ?? []) {
          const b = await backup(p);
          if (b) backups.push({ path: p, backup: b });
        }
        const r = await io.exec(op.file, op.args);
        if (r.error || r.code !== 0) {
          throw new Error(`${op.file} ${op.args.join(' ')} failed: ${r.error ?? (r.stderr.trim() || `exit ${r.code}`)}`);
        }
        tx.steps.push({ kind: 'exec', description: op.descriptionEn, undo: op.undo, backups });
      }
    }
  } catch (e) {
    tx.error = e instanceof Error ? e.message : String(e);
    await saveJournal(io, dataDir, journal);
    throw e;
  }
  await saveJournal(io, dataDir, journal);
  return tx;
}

export interface UndoResult {
  tx: Transaction;
  errors: string[];
}

/** Reverts a transaction (default: the most recent one not yet undone), steps in reverse order. */
export async function undoTransaction(io: FixIo, dataDir: string, id?: string): Promise<UndoResult | null> {
  const journal = await loadJournal(io, dataDir);
  const candidates = journal.transactions.filter((t) => !t.undoneAt);
  const tx = id ? candidates.find((t) => t.id === id) : candidates[candidates.length - 1];
  if (!tx) return null;
  const errors: string[] = [];
  for (const step of [...tx.steps].reverse()) {
    try {
      if (step.kind === 'file') {
        if (step.backup) await io.copyFile(step.backup, step.path);
        else await io.removeFile(step.path);
      } else if (step.undo) {
        const r = await io.exec(step.undo.file, step.undo.args);
        if (r.error || r.code !== 0) errors.push(`${step.undo.file} ${step.undo.args.join(' ')}: ${r.error ?? (r.stderr.trim() || `exit ${r.code}`)}`);
      }
    } catch (e) {
      errors.push(e instanceof Error ? e.message : String(e));
    }
  }
  tx.undoneAt = io.now().toISOString();
  await saveJournal(io, dataDir, journal);
  return { tx, errors };
}

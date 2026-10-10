import { describe, expect, it } from 'vitest';
import { applyPlan, describePlan, loadJournal, undoTransaction, validatePlanSafety, UnsafePlanError, type FixIo } from '../src/core/fixes/executor.js';
import { findFix, FIX_DEFINITIONS, type FixPlan } from '../src/core/fixes/definitions.js';
import { FIXES } from '../src/core/fixes/catalog.js';
import type { ExecResult } from '../src/core/types.js';
import { fakeCtx, ok } from './helpers.js';

const HOME = 'C:\\Users\\test';
const DATA = `${HOME}\\.netfree-doctor`;

function memIo(initial: Record<string, string> = {}, execFn?: (f: string, a: string[]) => ExecResult) {
  const files = new Map(Object.entries(initial));
  const execLog: string[] = [];
  let t = Date.parse('2026-10-10T20:00:00Z');
  const io: FixIo = {
    readFile: async (p) => files.get(p) ?? null,
    writeFile: async (p, c) => void files.set(p, c),
    copyFile: async (s, d) => {
      const v = files.get(s);
      if (v === undefined) throw new Error(`ENOENT ${s}`);
      files.set(d, v);
    },
    removeFile: async (p) => void files.delete(p),
    fileExists: async (p) => files.has(p),
    mkdirp: async () => {},
    exec: async (f, a) => {
      execLog.push([f, ...a].join(' '));
      return execFn ? execFn(f, a) : ok();
    },
    now: () => new Date((t += 1000)),
    join: (...p) => p.join('\\'),
    basename: (p) => p.split(/[\\/]/).pop() ?? p,
    dirname: (p) => p.split(/[\\/]/).slice(0, -1).join('\\'),
  };
  return { io, files, execLog };
}

function plan(ops: FixPlan['ops']): FixPlan {
  return { fix: FIXES.firefox, ops, notesHe: [], notesEn: [] };
}

const userJs = `${HOME}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\a\\user.js`;

describe('safety validation', () => {
  it('rejects plans that disable TLS verification or bypass the filter', () => {
    const bad = [
      { kind: 'exec' as const, file: 'setx', args: ['NODE_TLS_REJECT_UNAUTHORIZED', '0'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec' as const, file: 'git', args: ['config', '--global', 'http.sslVerify', 'false'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec' as const, file: 'npm', args: ['config', 'set', 'strict-ssl', 'false'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec' as const, file: 'pip', args: ['install', '--trusted-host', 'pypi.org', 'x'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec' as const, file: 'setx', args: ['HTTPS_PROXY', 'socks5://1.2.3.4'], descriptionHe: '', descriptionEn: '', undo: null },
    ];
    for (const op of bad) expect(validatePlanSafety(plan([op]), HOME).length).toBeGreaterThan(0);
  });

  it('rejects writes outside the user profile', () => {
    const v = validatePlanSafety(plan([{ kind: 'writeFile', path: 'C:\\Windows\\x.pem', content: '', descriptionHe: '', descriptionEn: '' }]), HOME);
    expect(v[0]?.whyEn).toMatch(/outside the user profile/);
  });

  it('allows the safe operations the tool actually uses', () => {
    const good = plan([
      { kind: 'writeFile', path: userJs, content: 'user_pref("security.enterprise_roots.enabled", true);', descriptionHe: '', descriptionEn: '' },
      { kind: 'exec', file: 'git', args: ['config', '--global', '--unset', 'http.sslVerify'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec', file: 'git', args: ['config', '--global', 'http.sslBackend', 'schannel'], descriptionHe: '', descriptionEn: '', undo: null },
      { kind: 'exec', file: 'cmd.exe', args: ['/d', '/c', 'npm', 'config', 'delete', 'strict-ssl'], descriptionHe: '', descriptionEn: '', undo: null },
    ]);
    expect(validatePlanSafety(good, HOME)).toEqual([]);
  });
});

describe('apply / undo with journal and backups', () => {
  it('backs up an existing file, writes, and restores on undo', async () => {
    const { io, files } = memIo({ [userJs]: 'user_pref("a", 1);\n' });
    const p = plan([{ kind: 'writeFile', path: userJs, content: 'NEW', descriptionHe: 'x', descriptionEn: 'x' }]);
    const tx = await applyPlan(io, DATA, HOME, p);
    expect(files.get(userJs)).toBe('NEW');
    const step = tx.steps[0]!;
    expect(step.kind === 'file' && step.backup).toBeTruthy();
    expect(files.get((step as { backup: string }).backup)).toBe('user_pref("a", 1);\n');
    const journal = await loadJournal(io, DATA);
    expect(journal.transactions).toHaveLength(1);

    const u = await undoTransaction(io, DATA);
    expect(u?.errors).toEqual([]);
    expect(files.get(userJs)).toBe('user_pref("a", 1);\n');
    expect((await loadJournal(io, DATA)).transactions[0]!.undoneAt).toBeTruthy();
    expect(await undoTransaction(io, DATA)).toBeNull();
  });

  it('deletes files that did not exist before on undo', async () => {
    const { io, files } = memIo();
    const target = `${DATA}\\netfree-ca.pem`;
    await applyPlan(io, DATA, HOME, plan([{ kind: 'writeFile', path: target, content: 'PEM', descriptionHe: '', descriptionEn: '' }]));
    expect(files.has(target)).toBe(true);
    await undoTransaction(io, DATA);
    expect(files.has(target)).toBe(false);
  });

  it('runs undo commands in reverse order and backs up config files', async () => {
    const gitconfig = `${HOME}\\.gitconfig`;
    const { io, execLog } = memIo({ [gitconfig]: '[http]\n' });
    const p = plan([
      { kind: 'exec', file: 'setx', args: ['A', '1'], descriptionHe: '', descriptionEn: '', undo: { file: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'A', '/f'] } },
      { kind: 'exec', file: 'git', args: ['config', '--global', 'http.sslBackend', 'schannel'], descriptionHe: '', descriptionEn: '', undo: { file: 'git', args: ['config', '--global', '--unset', 'http.sslBackend'] }, backupPaths: [gitconfig] },
    ]);
    const tx = await applyPlan(io, DATA, HOME, p);
    expect((tx.steps[1] as { backups: unknown[] }).backups).toHaveLength(1);
    execLog.length = 0;
    await undoTransaction(io, DATA, tx.id);
    expect(execLog).toEqual(['git config --global --unset http.sslBackend', 'reg delete HKCU\\Environment /v A /f']);
  });

  it('refuses unsafe plans before touching anything', async () => {
    const { io, files, execLog } = memIo();
    const p = plan([{ kind: 'exec', file: 'setx', args: ['NODE_TLS_REJECT_UNAUTHORIZED', '0'], descriptionHe: '', descriptionEn: '', undo: null }]);
    await expect(applyPlan(io, DATA, HOME, p)).rejects.toBeInstanceOf(UnsafePlanError);
    expect(execLog).toEqual([]);
    expect(files.size).toBe(0);
  });

  it('stops at a failing step and journals what was done', async () => {
    const { io } = memIo({}, (f) => (f === 'git' ? { code: 1, stdout: '', stderr: 'boom' } : ok()));
    const p = plan([
      { kind: 'writeFile', path: `${DATA}\\x.pem`, content: 'x', descriptionHe: '', descriptionEn: '' },
      { kind: 'exec', file: 'git', args: ['config'], descriptionHe: '', descriptionEn: '', undo: null },
    ]);
    await expect(applyPlan(io, DATA, HOME, p)).rejects.toThrow(/boom/);
    const j = await loadJournal(io, DATA);
    expect(j.transactions[0]!.steps).toHaveLength(1);
    expect(j.transactions[0]!.error).toMatch(/boom/);
  });

  it('describes a plan for dry-run in both languages', () => {
    const p = plan([
      { kind: 'exec', file: 'git', args: ['config', '--global', 'http.sslBackend', 'schannel'], descriptionHe: 'עברית', descriptionEn: 'english', undo: { file: 'git', args: ['config', '--global', '--unset', 'http.sslBackend'] } },
    ]);
    expect(describePlan(p, 'he').join('\n')).toContain('ביטול: git config --global --unset http.sslBackend');
    expect(describePlan(p, 'en')[0]).toBe('1. english');
  });
});

describe('fix definitions (plans built with a fake ctx)', () => {
  it('every check-offered fix has a definition', () => {
    for (const f of Object.values(FIXES)) expect(findFix(f.id)).toBeDefined();
    expect(FIX_DEFINITIONS).toHaveLength(4);
  });

  it('git-schannel plans schannel + removing sslVerify=false, with undo', async () => {
    const ctx = fakeCtx({
      exec: (f, a) => {
        if (f !== 'git') return undefined;
        if (a[0] === '--version') return ok('git version 2.55');
        const key = a[a.length - 1];
        if (key === 'http.sslVerify') return ok('false');
        return { code: 1, stdout: '', stderr: '' };
      },
    });
    const p = await findFix('git-schannel')!.plan(ctx);
    expect(p.blockerEn).toBeUndefined();
    expect(p.ops.map((o) => (o.kind === 'exec' ? o.args.join(' ') : ''))).toEqual([
      'config --global http.sslBackend schannel',
      'config --global --unset http.sslVerify',
    ]);
    expect(validatePlanSafety(p, ctx.homeDir)).toEqual([]);
  });

  it('firefox fix refuses while Firefox is running', async () => {
    const base = 'C:\\Users\\test\\AppData\\Roaming\\Mozilla\\Firefox';
    const prof = `${base}\\Profiles\\abc`;
    const ctx = fakeCtx({
      env: { APPDATA: 'C:\\Users\\test\\AppData\\Roaming' },
      files: { [`${base}\\profiles.ini`]: '[Profile0]\nName=p\nIsRelative=1\nPath=Profiles/abc\n' },
      dirs: { [prof]: [] },
      exec: (f) => (f === 'tasklist' ? ok('firefox.exe   1234 Console') : undefined),
    });
    const p = await findFix('firefox-enterprise-roots')!.plan(ctx);
    expect(p.ops).toHaveLength(1);
    expect(p.ops[0]!.kind === 'writeFile' && p.ops[0]!.content).toContain('user_pref("security.enterprise_roots.enabled", true);');
    expect(p.blockerEn).toMatch(/running/);
  });

  it('node fix writes a bundle under the user profile and sets the user env var (reversible)', async () => {
    const ctx = fakeCtx({ exec: (f, a) => (f === 'cmd.exe' ? ok(a.includes('strict-ssl') ? 'true' : 'null') : undefined) });
    const p = await findFix('node-extra-ca')!.plan(ctx);
    expect(p.ops[0]).toMatchObject({ kind: 'writeFile', path: 'C:\\Users\\test\\.netfree-doctor\\netfree-ca.pem' });
    expect(p.ops[1]).toMatchObject({ kind: 'exec', file: 'setx', args: ['NODE_EXTRA_CA_CERTS', 'C:\\Users\\test\\.netfree-doctor\\netfree-ca.pem'] });
    expect(p.ops[1]!.kind === 'exec' && p.ops[1]!.undo?.file).toBe('reg');
    expect(validatePlanSafety(p, ctx.homeDir)).toEqual([]);
  });
});

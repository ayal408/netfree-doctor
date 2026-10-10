import type { Ctx, FixAction, FixOp } from '../types.js';
import { FIXES } from './catalog.js';
import { readFirefoxProfiles } from '../checks/firefox.js';
import { ENTERPRISE_ROOTS_PREF, upsertUserPref } from '../parsers/firefox.js';
import { bundlePath, coverageOf, coverageWorks, joinPath, netfreePem, readEnvVar, stripQuotes, wantedCerts } from '../checks/shared.js';
import { readNpmState } from '../checks/node.js';
import { findPythons, probePython, pythonBundlePath } from '../checks/python.js';
import { gitConfigGet } from '../checks/git.js';
import { combinePem, splitPem } from '../parsers/certs.js';

export interface FixPlan {
  fix: FixAction;
  ops: FixOp[];
  /** Informational notes shown with the dry-run. */
  notesHe: string[];
  notesEn: string[];
  /** When set, the fix cannot be applied right now (reason). */
  blockerHe?: string;
  blockerEn?: string;
}

export interface FixDefinition extends FixAction {
  plan(ctx: Ctx): Promise<FixPlan>;
}

function emptyPlan(fix: FixAction): FixPlan {
  return { fix, ops: [], notesHe: [], notesEn: [] };
}

/** Ops that set (or restore) a persistent per-user environment variable on Windows. */
export async function setUserEnvOp(ctx: Ctx, name: string, value: string): Promise<FixOp> {
  const prev = await ctx.getUserEnv(name);
  return {
    kind: 'exec',
    file: 'setx',
    args: [name, value],
    descriptionHe: `הגדרת משתנה סביבה של המשתמש: ${name}=${value}${prev ? ` (הערך הקודם: ${prev})` : ''}`,
    descriptionEn: `Set user environment variable ${name}=${value}${prev ? ` (previous: ${prev})` : ''}`,
    undo: prev ? { file: 'setx', args: [name, prev] } : { file: 'reg', args: ['delete', 'HKCU\\Environment', '/v', name, '/f'] },
  };
}

const firefoxFix: FixDefinition = {
  ...FIXES.firefox,
  async plan(ctx) {
    const plan = emptyPlan(FIXES.firefox);
    const profiles = (await readFirefoxProfiles(ctx)) ?? [];
    for (const p of profiles) {
      if (p.effective === true) continue;
      const userJsPath = joinPath(ctx, p.dir, 'user.js');
      const current = (await ctx.readFile(userJsPath)) ?? '';
      plan.ops.push({
        kind: 'writeFile',
        path: userJsPath,
        content: upsertUserPref(current, ENTERPRISE_ROOTS_PREF, true),
        descriptionHe: `כתיבת user_pref("${ENTERPRISE_ROOTS_PREF}", true) לקובץ ${userJsPath} (פרופיל "${p.name}")`,
        descriptionEn: `Write user_pref("${ENTERPRISE_ROOTS_PREF}", true) to ${userJsPath} (profile "${p.name}")`,
      });
    }
    if (profiles.length === 0) {
      plan.blockerHe = 'לא נמצאו פרופילים של Firefox.';
      plan.blockerEn = 'No Firefox profiles found.';
    } else if (plan.ops.length === 0) {
      plan.blockerHe = 'אין מה לתקן: כל הפרופילים כבר מוגדרים.';
      plan.blockerEn = 'Nothing to fix: all profiles are already configured.';
    } else if (ctx.platform === 'win32') {
      const tl = await ctx.exec('tasklist', ['/FI', 'IMAGENAME eq firefox.exe', '/NH'], 10000);
      if (/firefox\.exe/i.test(tl.stdout)) {
        plan.blockerHe = 'Firefox פתוח כרגע. סגרו אותו ונסו שוב (אחרת הוא עלול לדרוס את השינוי).';
        plan.blockerEn = 'Firefox is running. Close it and try again (otherwise it may overwrite the change).';
      }
    }
    plan.notesHe.push('השינוי ייכנס לתוקף בפתיחה הבאה של Firefox.');
    plan.notesEn.push('Takes effect next time Firefox starts.');
    return plan;
  },
};

const nodeFix: FixDefinition = {
  ...FIXES.node,
  async plan(ctx) {
    const plan = emptyPlan(FIXES.node);
    const target = bundlePath(ctx);
    const nf = await netfreePem(ctx);
    if (splitPem(nf).length === 0) {
      plan.blockerHe = 'לא הצלחנו להשיג את תעודות נטפרי (netfree.link לא נגיש ואין עותק שמור).';
      plan.blockerEn = 'Could not obtain the Netfree certificates (netfree.link unreachable and no cache).';
      return plan;
    }
    // Keep whatever the current NODE_EXTRA_CA_CERTS file trusts, so nothing that worked breaks.
    const extra = await readEnvVar(ctx, 'NODE_EXTRA_CA_CERTS');
    const parts: string[] = [];
    if (extra.effective && stripQuotes(extra.effective).toLowerCase() !== target.toLowerCase()) {
      const existing = await ctx.readFile(stripQuotes(extra.effective));
      if (existing) {
        parts.push(existing);
        plan.notesHe.push(`התעודות מהקובץ הקיים ${extra.effective} נשמרות בקובץ החדש.`);
        plan.notesEn.push(`Certificates from the existing file ${extra.effective} are kept in the new bundle.`);
      }
    }
    parts.push(nf);
    const content = combinePem(parts);
    plan.ops.push({
      kind: 'writeFile',
      path: target,
      content,
      descriptionHe: `כתיבת קובץ תעודות משולב (${splitPem(content).length} תעודות) אל ${target}`,
      descriptionEn: `Write a combined CA file (${splitPem(content).length} certs) to ${target}`,
    });
    if (ctx.platform === 'win32') {
      if ((await ctx.getUserEnv('NODE_EXTRA_CA_CERTS')) !== target) plan.ops.push(await setUserEnvOp(ctx, 'NODE_EXTRA_CA_CERTS', target));
    } else {
      plan.notesHe.push(`הוסיפו לקובץ הפרופיל של המעטפת: export NODE_EXTRA_CA_CERTS="${target}"`);
      plan.notesEn.push(`Add to your shell profile: export NODE_EXTRA_CA_CERTS="${target}"`);
    }
    const npm = await readNpmState(ctx);
    const npmrc = joinPath(ctx, ctx.homeDir, '.npmrc');
    if (npm?.strictSsl === false) {
      plan.ops.push({
        kind: 'exec',
        file: ctx.platform === 'win32' ? 'cmd.exe' : 'npm',
        args: [...(ctx.platform === 'win32' ? ['/d', '/c', 'npm'] : []), 'config', 'delete', 'strict-ssl'],
        descriptionHe: 'ביטול strict-ssl=false ב-npm (החזרת בדיקת האבטחה)',
        descriptionEn: 'Remove npm strict-ssl=false (re-enable TLS verification)',
        undo: { file: ctx.platform === 'win32' ? 'cmd.exe' : 'npm', args: [...(ctx.platform === 'win32' ? ['/d', '/c', 'npm'] : []), 'config', 'set', 'strict-ssl', 'false'] },
        backupPaths: [npmrc],
      });
    }
    if (npm?.cafile) {
      const { live, official } = await wantedCerts(ctx);
      const text = await ctx.readFile(npm.cafile);
      if (text === null || !coverageWorks(coverageOf(text, live, official))) {
        plan.ops.push({
          kind: 'exec',
          file: ctx.platform === 'win32' ? 'cmd.exe' : 'npm',
          args: [...(ctx.platform === 'win32' ? ['/d', '/c', 'npm'] : []), 'config', 'delete', 'cafile'],
          descriptionHe: `הסרת cafile של npm (${npm.cafile}) שלא כולל את נטפרי, כדי ש-npm ישתמש ב-NODE_EXTRA_CA_CERTS`,
          descriptionEn: `Remove npm cafile (${npm.cafile}) which lacks Netfree, so npm uses NODE_EXTRA_CA_CERTS`,
          undo: { file: ctx.platform === 'win32' ? 'cmd.exe' : 'npm', args: [...(ctx.platform === 'win32' ? ['/d', '/c', 'npm'] : []), 'config', 'set', 'cafile', npm.cafile] },
          backupPaths: [npmrc],
        });
      }
    }
    plan.notesHe.push('יש לפתוח מחדש חלונות טרמינל / VS Code כדי שההגדרה תיכנס לתוקף.');
    plan.notesEn.push('Reopen terminals / VS Code for the setting to take effect.');
    return plan;
  },
};

const pythonFix: FixDefinition = {
  ...FIXES.python,
  async plan(ctx) {
    const plan = emptyPlan(FIXES.python);
    const py = (await findPythons(ctx))[0];
    if (!py) {
      plan.blockerHe = 'Python לא נמצא.';
      plan.blockerEn = 'Python not found.';
      return plan;
    }
    const probe = await probePython(ctx, py.path);
    if (!probe?.has_pip) {
      plan.blockerHe = `pip לא מותקן עבור ${py.path}.`;
      plan.blockerEn = `pip is not installed for ${py.path}.`;
      return plan;
    }
    const certifiText = probe.certifi ? await ctx.readFile(probe.certifi) : null;
    const nf = await netfreePem(ctx);
    if (splitPem(nf).length === 0) {
      plan.blockerHe = 'לא הצלחנו להשיג את תעודות נטפרי.';
      plan.blockerEn = 'Could not obtain the Netfree certificates.';
      return plan;
    }
    if (!certifiText) {
      plan.notesHe.push('לא נמצא certifi; הקובץ יכיל רק את תעודות נטפרי (מספיק כשכל התעבורה עוברת דרך נטפרי).');
      plan.notesEn.push('certifi not found; the bundle will contain only Netfree roots (enough when all traffic goes through Netfree).');
    }
    const target = pythonBundlePath(ctx);
    const content = combinePem([certifiText ?? '', nf]);
    plan.ops.push({
      kind: 'writeFile',
      path: target,
      content,
      descriptionHe: `כתיבת קובץ תעודות משולב (certifi + נטפרי, ${splitPem(content).length} תעודות) אל ${target}`,
      descriptionEn: `Write a combined bundle (certifi + Netfree, ${splitPem(content).length} certs) to ${target}`,
    });
    const prev = await ctx.exec(py.path, ['-m', 'pip', 'config', '--user', 'get', 'global.cert'], 30000);
    const prevVal = !prev.error && prev.code === 0 ? stripQuotes(prev.stdout.trim()) : '';
    const pipIni =
      ctx.platform === 'win32' && ctx.env.APPDATA ? joinPath(ctx, ctx.env.APPDATA, 'pip', 'pip.ini') : joinPath(ctx, ctx.homeDir, '.config', 'pip', 'pip.conf');
    plan.ops.push({
      kind: 'exec',
      file: py.path,
      args: ['-m', 'pip', 'config', '--user', 'set', 'global.cert', target],
      descriptionHe: `pip config --user set global.cert "${target}"${prevVal ? ` (הערך הקודם: ${prevVal})` : ''}`,
      descriptionEn: `pip config --user set global.cert "${target}"${prevVal ? ` (previous: ${prevVal})` : ''}`,
      undo: prevVal
        ? { file: py.path, args: ['-m', 'pip', 'config', '--user', 'set', 'global.cert', prevVal] }
        : { file: py.path, args: ['-m', 'pip', 'config', '--user', 'unset', 'global.cert'] },
      backupPaths: [pipIni],
    });
    plan.notesHe.push(`לספריית requests אפשר להגדיר בנוסף: setx REQUESTS_CA_BUNDLE "${target}"`);
    plan.notesEn.push(`For requests you can additionally run: setx REQUESTS_CA_BUNDLE "${target}"`);
    return plan;
  },
};

const gitFix: FixDefinition = {
  ...FIXES.git,
  async plan(ctx) {
    const plan = emptyPlan(FIXES.git);
    if (ctx.platform !== 'win32') {
      plan.blockerHe = 'schannel זמין רק ב-Windows.';
      plan.blockerEn = 'schannel is only available on Windows.';
      return plan;
    }
    const ver = await ctx.exec('git', ['--version'], 10000);
    if (ver.error || ver.code !== 0) {
      plan.blockerHe = 'Git לא נמצא.';
      plan.blockerEn = 'Git not found.';
      return plan;
    }
    const gitconfig = joinPath(ctx, ctx.homeDir, '.gitconfig');
    const prevBackend = await gitConfigGet(ctx, 'http.sslBackend', '--global');
    const effectiveBackend = await gitConfigGet(ctx, 'http.sslBackend');
    if (effectiveBackend?.toLowerCase() !== 'schannel') {
      plan.ops.push({
        kind: 'exec',
        file: 'git',
        args: ['config', '--global', 'http.sslBackend', 'schannel'],
        descriptionHe: `git config --global http.sslBackend schannel${prevBackend ? ` (הערך הקודם: ${prevBackend})` : ''}`,
        descriptionEn: `git config --global http.sslBackend schannel${prevBackend ? ` (previous: ${prevBackend})` : ''}`,
        undo: prevBackend
          ? { file: 'git', args: ['config', '--global', 'http.sslBackend', prevBackend] }
          : { file: 'git', args: ['config', '--global', '--unset', 'http.sslBackend'] },
        backupPaths: [gitconfig],
      });
    }
    const verify = await gitConfigGet(ctx, 'http.sslVerify', '--global');
    if (verify?.toLowerCase() === 'false') {
      plan.ops.push({
        kind: 'exec',
        file: 'git',
        args: ['config', '--global', '--unset', 'http.sslVerify'],
        descriptionHe: 'הסרת http.sslVerify=false (החזרת בדיקת האבטחה של Git)',
        descriptionEn: 'Remove http.sslVerify=false (re-enable Git TLS verification)',
        undo: { file: 'git', args: ['config', '--global', 'http.sslVerify', 'false'] },
        backupPaths: [gitconfig],
      });
    }
    if (plan.ops.length === 0) {
      plan.blockerHe = 'אין מה לתקן: Git כבר מוגדר ל-schannel.';
      plan.blockerEn = 'Nothing to fix: Git already uses schannel.';
    }
    plan.notesHe.push('schannel משתמש במאגר התעודות של Windows, כך שגם תעודות נטפרי עתידיות יעבדו אוטומטית.');
    plan.notesEn.push('schannel uses the Windows store, so future Netfree roots keep working automatically.');
    return plan;
  },
};

export const FIX_DEFINITIONS: readonly FixDefinition[] = [firefoxFix, nodeFix, pythonFix, gitFix];

export function findFix(id: string): FixDefinition | undefined {
  return FIX_DEFINITIONS.find((f) => f.id === id);
}


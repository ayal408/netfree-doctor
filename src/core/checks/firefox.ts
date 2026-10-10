import type { Check, CheckResult, Ctx } from '../types.js';
import { ENTERPRISE_ROOTS_PREF, parsePrefs, parseProfilesIni, type PrefValue } from '../parsers/firefox.js';
import { FIXES } from '../fixes/catalog.js';
import { joinPath } from './shared.js';

export function firefoxBaseDir(ctx: Ctx): string | null {
  if (ctx.platform === 'win32') {
    const appData = ctx.env.APPDATA;
    return appData ? joinPath(ctx, appData, 'Mozilla', 'Firefox') : null;
  }
  if (ctx.platform === 'darwin') return joinPath(ctx, ctx.homeDir, 'Library', 'Application Support', 'Firefox');
  return joinPath(ctx, ctx.homeDir, '.mozilla', 'firefox');
}

export interface FirefoxProfileState {
  name: string;
  dir: string;
  isDefault: boolean;
  prefsValue: PrefValue | undefined;
  userJsValue: PrefValue | undefined;
  /** Effective value: user.js overrides prefs.js on every start. */
  effective: PrefValue | undefined;
}

export async function readFirefoxProfiles(ctx: Ctx): Promise<FirefoxProfileState[] | null> {
  const base = firefoxBaseDir(ctx);
  if (!base) return null;
  const ini = await ctx.readFile(joinPath(ctx, base, 'profiles.ini'));
  if (ini === null) return null;
  const out: FirefoxProfileState[] = [];
  for (const p of parseProfilesIni(ini)) {
    const rel = p.path.replace(/[\\/]/g, ctx.platform === 'win32' ? '\\' : '/');
    const dir = p.isRelative ? joinPath(ctx, base, rel) : rel;
    if (!(await ctx.fileExists(dir))) continue;
    const prefs = parsePrefs((await ctx.readFile(joinPath(ctx, dir, 'prefs.js'))) ?? '');
    const user = parsePrefs((await ctx.readFile(joinPath(ctx, dir, 'user.js'))) ?? '');
    const prefsValue = prefs.get(ENTERPRISE_ROOTS_PREF);
    const userJsValue = user.get(ENTERPRISE_ROOTS_PREF);
    out.push({ name: p.name, dir, isDefault: p.isDefault, prefsValue, userJsValue, effective: userJsValue ?? prefsValue });
  }
  return out;
}

export const firefoxCheck: Check = {
  id: 'firefox',
  titleHe: 'Firefox',
  titleEn: 'Firefox',
  async run(ctx): Promise<CheckResult> {
    const profiles = await readFirefoxProfiles(ctx);
    if (!profiles || profiles.length === 0) {
      return {
        status: 'info',
        summaryHe: 'Firefox לא נמצא במחשב (או שאין לו פרופילים).',
        summaryEn: 'Firefox not found (or it has no profiles).',
      };
    }
    const detailsHe: string[] = [];
    const detailsEn: string[] = [];
    for (const p of profiles) {
      const v = p.effective === undefined ? 'לא מוגדר' : String(p.effective);
      const vEn = p.effective === undefined ? 'not set' : String(p.effective);
      detailsHe.push(`פרופיל "${p.name}"${p.isDefault ? ' (ברירת מחדל)' : ''}: ${ENTERPRISE_ROOTS_PREF} = ${v}`);
      detailsEn.push(`Profile "${p.name}"${p.isDefault ? ' (default)' : ''}: ${ENTERPRISE_ROOTS_PREF} = ${vEn}`);
    }
    const explicitFalse = profiles.filter((p) => p.effective === false);
    const unset = profiles.filter((p) => p.effective === undefined);
    const data = { profiles: profiles.map((p) => ({ name: p.name, dir: p.dir, value: p.effective ?? null })) };

    if (explicitFalse.length > 0) {
      return {
        status: 'fail',
        summaryHe: `ב-${explicitFalse.length} פרופילים של Firefox כבוי השימוש בתעודות של Windows, ולכן Firefox יציג שגיאות אבטחה באתרים מוצפנים.`,
        summaryEn: `${explicitFalse.length} Firefox profile(s) have Windows-certificate trust disabled, so Firefox shows security errors on HTTPS sites.`,
        detailsHe,
        detailsEn,
        fix: FIXES.firefox,
        data,
      };
    }
    if (unset.length > 0) {
      return {
        status: 'warn',
        summaryHe:
          'ב-Firefox לא מוגדר במפורש שימוש בתעודות של Windows. בגרסאות חדשות זה בדרך כלל פעיל כברירת מחדל, אבל הגדרה מפורשת מונעת הפתעות.',
        summaryEn:
          'Firefox is not explicitly set to use Windows certificates. Recent versions usually default to on, but setting it explicitly avoids surprises.',
        detailsHe,
        detailsEn,
        fix: FIXES.firefox,
        data,
      };
    }
    return {
      status: 'ok',
      summaryHe: 'Firefox מוגדר להשתמש בתעודות של Windows (כולל של נטפרי).',
      summaryEn: 'Firefox is set to use the Windows certificate store (including Netfree).',
      detailsHe,
      detailsEn,
      data,
    };
  },
};

import type { Check, CheckResult, Ctx } from '../types.js';
import { joinPath } from './shared.js';

export const MAGISK_ANDROID14 = 'https://github.com/Sivan22/ca-netfree-android14/releases';
export const MAGISK_OLDER = 'https://github.com/Sivan22/ca-netfree';

export interface EmulatorFound {
  name: string;
  path: string;
}

export async function findEmulators(ctx: Ctx): Promise<EmulatorFound[]> {
  if (ctx.platform !== 'win32') return [];
  const found: EmulatorFound[] = [];
  // LDPlayer: C:\LDPlayer\<version dir>\ldconsole.exe
  for (const root of ['C:\\LDPlayer', 'D:\\LDPlayer']) {
    for (const sub of await ctx.listDir(root)) {
      const p = joinPath(ctx, root, sub, 'ldconsole.exe');
      if (await ctx.fileExists(p)) found.push({ name: `LDPlayer (${sub})`, path: p });
    }
  }
  // Android Studio emulator
  const sdkRoots = [ctx.env.ANDROID_HOME, ctx.env.ANDROID_SDK_ROOT, ctx.env.LOCALAPPDATA ? joinPath(ctx, ctx.env.LOCALAPPDATA, 'Android', 'Sdk') : undefined].filter(
    (x): x is string => !!x,
  );
  for (const sdk of [...new Set(sdkRoots)]) {
    const p = joinPath(ctx, sdk, 'emulator', 'emulator.exe');
    if (await ctx.fileExists(p)) {
      found.push({ name: 'Android Studio Emulator', path: p });
      break;
    }
  }
  // BlueStacks
  const pf = ctx.env.ProgramFiles ?? 'C:\\Program Files';
  for (const dir of ['BlueStacks_nxt', 'BlueStacks', 'BlueStacks_msi5']) {
    const p = joinPath(ctx, pf, dir, 'HD-Player.exe');
    if (await ctx.fileExists(p)) found.push({ name: 'BlueStacks', path: p });
  }
  return found;
}

export const androidCheck: Check = {
  id: 'android',
  titleHe: 'אמולטורים של אנדרואיד',
  titleEn: 'Android emulators',
  async run(ctx): Promise<CheckResult> {
    const found = await findEmulators(ctx);
    if (found.length === 0) {
      return { status: 'info', summaryHe: 'לא נמצאו אמולטורים של אנדרואיד (LDPlayer / Android Studio / BlueStacks).', summaryEn: 'No Android emulators found.' };
    }
    return {
      status: 'info',
      summaryHe: `נמצאו אמולטורים: ${found.map((f) => f.name).join(', ')}. אפליקציות באנדרואיד 7 ומעלה לא סומכות על תעודות שהמשתמש התקין, ולכן רוב האפליקציות לא יעבדו דרך נטפרי בלי תעודת מערכת.`,
      summaryEn: `Emulators found: ${found.map((f) => f.name).join(', ')}. Apps on Android 7+ ignore user-installed CAs, so most apps fail through Netfree without a system CA.`,
      detailsHe: [
        ...found.map((f) => `${f.name}: ${f.path}`),
        'התקנת התעודה כ"תעודת משתמש" (הגדרות ← אבטחה) מספיקה רק לדפדפן ולאפליקציות מעטות.',
        'כדי שכל האפליקציות יעבדו צריך להתקין את התעודה כתעודת מערכת, וזה דורש הרשאות root (ברוב האמולטורים אפשר להפעיל root בהגדרות) ומודול Magisk:',
        `  אנדרואיד 14: ${MAGISK_ANDROID14}`,
        `  אנדרואיד ישן יותר: ${MAGISK_OLDER}`,
        'הכלי לא מבצע root ולא משנה את האמולטור. זו פעולה ידנית באחריותכם.',
      ],
      detailsEn: [
        ...found.map((f) => `${f.name}: ${f.path}`),
        'Installing the CA as a "user" certificate only helps the browser and a few apps.',
        'For all apps, install it as a system CA: this needs root (most emulators have a root toggle) and a Magisk module:',
        `  Android 14: ${MAGISK_ANDROID14}`,
        `  Older Android: ${MAGISK_OLDER}`,
        'This tool does not root or modify the emulator; it is a manual step.',
      ],
      data: { found },
    };
  },
};

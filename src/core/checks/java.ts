import type { Check, CheckResult, Ctx } from '../types.js';
import { parseWhere } from '../parsers/python.js';
import { joinPath } from './shared.js';

export async function findJava(ctx: Ctx): Promise<string[]> {
  const out = new Set<string>();
  const javaHome = ctx.env.JAVA_HOME;
  if (javaHome) {
    const p = joinPath(ctx, javaHome, 'bin', ctx.platform === 'win32' ? 'java.exe' : 'java');
    if (await ctx.fileExists(p)) out.add(p);
  }
  const w = await ctx.exec(ctx.platform === 'win32' ? 'where' : 'which', ['java'], 10000);
  if (!w.error && w.code === 0) {
    for (const p of ctx.platform === 'win32' ? parseWhere(w.stdout) : w.stdout.split('\n').map((s) => s.trim()).filter(Boolean)) {
      // Skip the Oracle "javapath" shim duplicates only if identical.
      out.add(p);
    }
  }
  return [...out];
}

export const javaCheck: Check = {
  id: 'java',
  titleHe: 'Java',
  titleEn: 'Java',
  async run(ctx): Promise<CheckResult> {
    const javas = await findJava(ctx);
    if (javas.length === 0) return { status: 'info', summaryHe: 'Java לא נמצא במחשב.', summaryEn: 'Java not found.' };
    const ver = await ctx.exec(javas[0]!, ['-version'], 15000);
    const verLine = (ver.stderr || ver.stdout).split(/\r?\n/)[0]?.trim() ?? '';
    const certDir = joinPath(ctx, ctx.dataDir, 'certs');
    const certFile = joinPath(ctx, certDir, 'root_ca_rsa.crt');
    const certFileX2 = joinPath(ctx, certDir, 'root_ca_x2_rsa.crt');
    const jto = `${ctx.env.JAVA_TOOL_OPTIONS ?? ''} ${(await ctx.getUserEnv('JAVA_TOOL_OPTIONS')) ?? ''}`;
    if (/trustStoreType=Windows-ROOT/i.test(jto)) {
      return {
        status: 'ok',
        summaryHe: 'Java מוגדר להשתמש במאגר התעודות של Windows (Windows-ROOT), ולכן מכיר את נטפרי.',
        summaryEn: 'Java is set to use the Windows certificate store (Windows-ROOT), so it trusts Netfree.',
        detailsHe: [`נמצא: ${javas.join(' ; ')}${verLine ? ` (${verLine})` : ''}`, `JAVA_TOOL_OPTIONS = ${jto.trim()}`],
        detailsEn: [`Found: ${javas.join(' ; ')}${verLine ? ` (${verLine})` : ''}`, `JAVA_TOOL_OPTIONS = ${jto.trim()}`],
        data: { javas, version: verLine, windowsRoot: true },
      };
    }
    const cmd = (alias: string, file: string) => `keytool -importcert -cacerts -alias ${alias} -file "${file}" -storepass changeit -noprompt`;
    return {
      status: 'info',
      summaryHe:
        'נמצא Java. ל-Java יש מאגר תעודות משלו (cacerts), ולכן צריך לייבא אליו את תעודת נטפרי או להגדיר לו להשתמש במאגר של Windows. הכלי לא עושה זאת אוטומטית.',
      summaryEn:
        'Java found. Java has its own CA store (cacerts), so the Netfree root must be imported or Java told to use the Windows store. Not automated.',
      detailsHe: [
        `נמצא: ${javas.join(' ; ')}${verLine ? ` (${verLine})` : ''}`,
        'אפשרות 1 (מומלצת, Java 11+): להשתמש במאגר של Windows:',
        '  setx JAVA_TOOL_OPTIONS "-Djavax.net.ssl.trustStoreType=Windows-ROOT"',
        'אפשרות 2: לייבא את התעודות (בחלון פקודה כמנהל, Java 9+; קובצי התעודות נשמרים בתיקייה של הכלי):',
        `  ${cmd('netfree-root-rsa', certFile)}`,
        `  ${cmd('netfree-root-x2-rsa', certFileX2)}`,
        'שימו לב: עדכון של Java מחליף את cacerts, ואז צריך לייבא שוב.',
      ],
      detailsEn: [
        `Found: ${javas.join(' ; ')}${verLine ? ` (${verLine})` : ''}`,
        'Option 1 (recommended, Java 11+): use the Windows store:',
        '  setx JAVA_TOOL_OPTIONS "-Djavax.net.ssl.trustStoreType=Windows-ROOT"',
        'Option 2: import the certificates (elevated prompt, Java 9+; cert files are cached in the tool folder):',
        `  ${cmd('netfree-root-rsa', certFile)}`,
        `  ${cmd('netfree-root-x2-rsa', certFileX2)}`,
        'Note: a Java update replaces cacerts; re-import afterwards.',
      ],
      data: { javas, version: verLine },
    };
  },
};

import type { Check, CheckOutcome, Ctx } from './types.js';
import { netfreeCheck } from './checks/netfree.js';
import { windowsStoreCheck } from './checks/windowsStore.js';
import { firefoxCheck } from './checks/firefox.js';
import { nodeCheck } from './checks/node.js';
import { pythonCheck } from './checks/python.js';
import { gitCheck } from './checks/git.js';
import { javaCheck } from './checks/java.js';
import { androidCheck } from './checks/android.js';

export const ALL_CHECKS: readonly Check[] = [
  netfreeCheck,
  windowsStoreCheck,
  firefoxCheck,
  nodeCheck,
  pythonCheck,
  gitCheck,
  javaCheck,
  androidCheck,
];

/** Runs one check; never throws (an exception becomes a 'fail' result). */
export async function runCheck(ctx: Ctx, check: Check): Promise<CheckOutcome> {
  const start = Date.now();
  try {
    const r = await check.run(ctx);
    return { id: check.id, titleHe: check.titleHe, titleEn: check.titleEn, durationMs: Date.now() - start, ...r };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      id: check.id,
      titleHe: check.titleHe,
      titleEn: check.titleEn,
      durationMs: Date.now() - start,
      status: 'fail',
      summaryHe: `הבדיקה נכשלה בשגיאה פנימית: ${msg}`,
      summaryEn: `The check crashed: ${msg}`,
    };
  }
}

/**
 * Runs checks concurrently (they are independent; the real ctx memoizes network probes),
 * reporting each as it finishes, and returns them in declaration order.
 */
export async function runChecks(
  ctx: Ctx,
  checks: readonly Check[] = ALL_CHECKS,
  onResult?: (o: CheckOutcome) => void,
): Promise<CheckOutcome[]> {
  return Promise.all(
    checks.map(async (c) => {
      const o = await runCheck(ctx, c);
      onResult?.(o);
      return o;
    }),
  );
}

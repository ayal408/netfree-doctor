/**
 * Minimal Electron shell around the same check engine as the CLI.
 * Fully offline UI (no CDN, strict CSP); all work happens in the main process via IPC.
 */
import { app, BrowserWindow, ipcMain, shell } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applyPlan,
  describePlan,
  diagnoseUrl,
  findFix,
  runChecks,
  undoTransaction,
  validatePlanSafety,
} from '../core/index.js';
import { createNodeCtx } from '../platform/nodeCtx.js';
import { createFixIo } from '../platform/fixIo.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function createWindow(): void {
  const win = new BrowserWindow({
    width: 980,
    height: 800,
    minWidth: 520,
    minHeight: 480,
    title: 'netfree-doctor',
    backgroundColor: '#f6f7f9',
    autoHideMenuBar: true,
    show: !process.env.NFD_GUI_SMOKE, // smoke test renders off-screen (no user interaction possible)
    webPreferences: {
      preload: path.join(here, 'preload.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  win.setMenu(null);
  // Never navigate the app window away; open https links in the user's browser instead.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  void win.loadFile(path.join(here, 'renderer', 'index.html'));

  // Developer smoke test: NFD_GUI_SMOKE=<file.png> runs the checks, saves a screenshot and quits.
  const smoke = process.env.NFD_GUI_SMOKE;
  if (smoke) {
    win.webContents.once('did-finish-load', async () => {
      await win.webContents.executeJavaScript("document.getElementById('run').click()");
      await new Promise((r) => setTimeout(r, Number(process.env.NFD_GUI_SMOKE_WAIT ?? 40000)));
      await win.webContents.executeJavaScript('window.scrollTo(0, 0)');
      const img = await win.webContents.capturePage();
      const { writeFile } = await import('node:fs/promises');
      await writeFile(smoke, img.toPNG());
      app.quit();
    });
  }
}

function registerIpc(): void {
  ipcMain.handle('checks:run', async (event) => {
    const ctx = createNodeCtx();
    return runChecks(ctx, undefined, (o) => event.sender.send('checks:result', o));
  });

  ipcMain.handle('url:check', async (_e, url: unknown) => diagnoseUrl(createNodeCtx(), String(url ?? '')));

  ipcMain.handle('fix:plan', async (_e, id: unknown) => {
    const def = findFix(String(id));
    if (!def) return { error: 'תיקון לא מוכר' };
    const ctx = createNodeCtx();
    const plan = await def.plan(ctx);
    const violations = validatePlanSafety(plan, ctx.homeDir);
    return {
      id: def.id,
      title: def.titleHe,
      note: def.noteHe ?? null,
      lines: describePlan(plan, 'he'),
      blocker: plan.blockerHe ?? null,
      violations: violations.map((v) => v.whyHe),
    };
  });

  ipcMain.handle('fix:apply', async (_e, id: unknown) => {
    const def = findFix(String(id));
    if (!def) return { ok: false, error: 'תיקון לא מוכר' };
    const ctx = createNodeCtx();
    const plan = await def.plan(ctx); // re-plan right before applying (state may have changed)
    if (plan.blockerHe) return { ok: false, error: plan.blockerHe };
    try {
      const tx = await applyPlan(createFixIo(), ctx.dataDir, ctx.homeDir, plan);
      return { ok: true, txId: tx.id };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  });

  ipcMain.handle('undo:last', async () => {
    const ctx = createNodeCtx();
    const r = await undoTransaction(createFixIo(), ctx.dataDir);
    if (!r) return { ok: false, error: 'אין תיקון לבטל.' };
    return { ok: r.errors.length === 0, fixId: r.tx.fixId, txId: r.tx.id, errors: r.errors };
  });

  ipcMain.handle('open:external', async (_e, url: unknown) => {
    const u = String(url ?? '');
    if (u.startsWith('https://')) await shell.openExternal(u);
  });
}

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

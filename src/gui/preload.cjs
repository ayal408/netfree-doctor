// Preload (CommonJS, sandboxed): exposes a tiny, explicit API to the renderer.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('doctor', {
  runChecks: () => ipcRenderer.invoke('checks:run'),
  onCheckResult: (cb) => {
    ipcRenderer.removeAllListeners('checks:result');
    ipcRenderer.on('checks:result', (_e, result) => cb(result));
  },
  checkUrl: (url) => ipcRenderer.invoke('url:check', url),
  planFix: (id) => ipcRenderer.invoke('fix:plan', id),
  applyFix: (id) => ipcRenderer.invoke('fix:apply', id),
  undoLast: () => ipcRenderer.invoke('undo:last'),
  openExternal: (url) => ipcRenderer.invoke('open:external', url),
});

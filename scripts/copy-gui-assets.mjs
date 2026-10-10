// Copies the static GUI files (HTML/CSS/JS renderer + CommonJS preload) into dist/gui.
import { cpSync, existsSync, mkdirSync } from 'node:fs';

const pairs = [
  ['src/gui/renderer', 'dist/gui/renderer'],
  ['src/gui/preload.cjs', 'dist/gui/preload.cjs'],
];
mkdirSync('dist/gui', { recursive: true });
for (const [from, to] of pairs) {
  if (existsSync(from)) cpSync(from, to, { recursive: true });
}
console.log('GUI assets copied.');

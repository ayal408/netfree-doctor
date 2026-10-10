import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { FixIo } from '../core/fixes/executor.js';
import { execCmd } from './nodeCtx.js';

/** Real file-system / process implementation of {@link FixIo}. */
export function createFixIo(): FixIo {
  return {
    readFile: (p) => fs.readFile(p, 'utf8').catch(() => null),
    writeFile: (p, c) => fs.writeFile(p, c, 'utf8'),
    copyFile: (s, d) => fs.copyFile(s, d),
    removeFile: (p) => fs.rm(p, { force: true }),
    fileExists: (p) =>
      fs
        .stat(p)
        .then(() => true)
        .catch(() => false),
    mkdirp: async (d) => {
      await fs.mkdir(d, { recursive: true });
    },
    exec: (f, a) => execCmd(f, a, 60000),
    now: () => new Date(),
    join: (...p) => path.join(...p),
    basename: (p) => path.basename(p),
    dirname: (p) => path.dirname(p),
  };
}

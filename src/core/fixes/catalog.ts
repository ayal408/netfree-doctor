import type { FixAction } from '../types.js';

/** Metadata of every fix the tool offers. Implementations live in ./definitions.ts */
export const FIXES = {
  firefox: {
    id: 'firefox-enterprise-roots',
    titleHe: 'להגדיר ל-Firefox להשתמש בתעודות של Windows',
    titleEn: 'Make Firefox trust the Windows certificate store',
    noteHe: 'יש לסגור את Firefox לפני התיקון.',
    noteEn: 'Close Firefox before applying.',
  },
  node: {
    id: 'node-extra-ca',
    titleHe: 'להגדיר ל-Node/npm את תעודות נטפרי (NODE_EXTRA_CA_CERTS)',
    titleEn: 'Configure Netfree CAs for Node/npm (NODE_EXTRA_CA_CERTS)',
    noteHe: 'ההגדרה תחול על חלונות/תוכנות שייפתחו מחדש אחרי התיקון.',
    noteEn: 'Takes effect in terminals/apps started after the fix.',
  },
  python: {
    id: 'python-pip-cert',
    titleHe: 'להגדיר ל-pip קובץ תעודות משולב (certifi + נטפרי)',
    titleEn: 'Point pip at a combined CA bundle (certifi + Netfree)',
  },
  git: {
    id: 'git-schannel',
    titleHe: 'להגדיר ל-Git להשתמש במאגר התעודות של Windows (schannel)',
    titleEn: 'Make Git use the Windows certificate store (schannel)',
  },
} as const satisfies Record<string, FixAction>;

export type FixId = (typeof FIXES)[keyof typeof FIXES]['id'];

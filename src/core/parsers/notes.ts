/**
 * Detection of notes / scripts that Netfree injects into allowed pages.
 *
 * Observed on chatgpt.com:
 *   <script src="https://netfree.link/injection-script/note-in-site.js" id="netfree-note-site"
 *           jsondata="%7B%22noteSite%22:%22...%22%2C%22noteSiteEn%22:%22...%22%7D">
 * The JSON contains `noteSite` (Hebrew) and `noteSiteEn` (English), with MediaWiki-style
 * links: [[Page|label]] which point to https://netfree.link/wiki/Page
 */

export interface WikiLink {
  page: string;
  label: string;
  url: string;
}

export interface InjectedNote {
  he?: string;
  en?: string;
  links: WikiLink[];
}

export interface InjectionInfo {
  notes: InjectedNote[];
  /** File names of injected netfree.link/injection-script/* scripts. */
  scripts: string[];
}

export const NETFREE_WIKI_BASE = 'https://netfree.link/wiki/';

export function wikiPageUrl(page: string): string {
  const normalized = page.trim().replace(/ /g, '_');
  // Keep ASCII readable; percent-encode anything else so the URL is copy/paste safe.
  return NETFREE_WIKI_BASE + encodeURIComponent(normalized).replace(/%2F/gi, '/');
}

/**
 * Converts [[Page|label]] / [[Page]] wiki links to plain text "label (url)" and returns
 * the links found.
 */
export function convertWikiLinks(text: string): { text: string; links: WikiLink[] } {
  const links: WikiLink[] = [];
  const out = text.replace(/\[\[([^\]|]+)(?:\|([^\]]*))?\]\]/g, (_m, page: string, label?: string) => {
    const url = wikiPageUrl(page);
    const lbl = (label ?? page).trim() || page.trim();
    links.push({ page: page.trim(), label: lbl, url });
    return `${lbl} (${url})`;
  });
  return { text: out, links };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function decodeHtmlEntities(s: string): string {
  return s
    .replace(/&quot;/g, '"')
    .replace(/&#34;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function unescapeJsonString(s: string): string {
  try {
    return JSON.parse(`"${s}"`) as string;
  } catch {
    return s;
  }
}

function noteFromObject(obj: Record<string, unknown>): InjectedNote | null {
  const rawHe = typeof obj.noteSite === 'string' ? obj.noteSite : undefined;
  const rawEn = typeof obj.noteSiteEn === 'string' ? obj.noteSiteEn : undefined;
  if (!rawHe && !rawEn) return null;
  const links: WikiLink[] = [];
  const note: InjectedNote = { links };
  if (rawHe) {
    const c = convertWikiLinks(rawHe);
    note.he = c.text;
    links.push(...c.links);
  }
  if (rawEn) {
    const c = convertWikiLinks(rawEn);
    note.en = c.text;
    links.push(...c.links);
  }
  return note;
}

/** Finds injected Netfree notes and scripts in an HTML body. */
export function parseInjectedNotes(html: string): InjectionInfo {
  const notes: InjectedNote[] = [];
  const seen = new Set<string>();

  const push = (n: InjectedNote | null) => {
    if (!n) return;
    const key = `${n.he ?? ''}|${n.en ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    notes.push(n);
  };

  // 1) jsondata="..." attributes (URL-encoded JSON).
  const attrRe = /jsondata\s*=\s*("([^"]*)"|'([^']*)')/gi;
  for (const m of html.matchAll(attrRe)) {
    const raw = decodeHtmlEntities(m[2] ?? m[3] ?? '');
    const decoded = safeDecode(raw);
    try {
      const parsed: unknown = JSON.parse(decoded);
      if (parsed && typeof parsed === 'object') push(noteFromObject(parsed as Record<string, unknown>));
    } catch {
      /* ignore malformed */
    }
  }

  // 2) Plain JSON embedded in the page ("noteSite":"...", "noteSiteEn":"...").
  if (notes.length === 0) {
    const he = /"noteSite"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(html);
    const en = /"noteSiteEn"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(html);
    if (he || en) {
      const obj: Record<string, unknown> = {};
      if (he?.[1] !== undefined) obj.noteSite = unescapeJsonString(he[1]);
      if (en?.[1] !== undefined) obj.noteSiteEn = unescapeJsonString(en[1]);
      push(noteFromObject(obj));
    }
  }

  const scripts = new Set<string>();
  for (const m of html.matchAll(/netfree\.link\/injection-script\/([\w.-]+)/gi)) {
    if (m[1]) scripts.add(m[1]);
  }

  return { notes, scripts: [...scripts] };
}

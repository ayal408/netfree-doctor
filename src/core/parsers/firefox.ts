/** Parsers for Firefox profiles.ini and prefs.js / user.js. */

export interface FirefoxProfile {
  name: string;
  /** Path as written in profiles.ini (may be relative). */
  path: string;
  isRelative: boolean;
  isDefault: boolean;
}

/** Parses an INI file into sections. */
export function parseIni(text: string): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  let current: Record<string, string> | null = null;
  for (const rawLine of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;
    const sec = /^\[(.+)\]$/.exec(line);
    if (sec?.[1]) {
      current = out[sec[1]] = out[sec[1]] ?? {};
      continue;
    }
    const eq = line.indexOf('=');
    if (eq > 0 && current) current[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

export function parseProfilesIni(text: string): FirefoxProfile[] {
  const ini = parseIni(text);
  const installDefaults = new Set(
    Object.entries(ini)
      .filter(([k]) => k.startsWith('Install'))
      .map(([, v]) => v.Default)
      .filter((v): v is string => !!v),
  );
  const profiles: FirefoxProfile[] = [];
  for (const [section, v] of Object.entries(ini)) {
    if (!/^Profile\d+$/.test(section) || !v.Path) continue;
    profiles.push({
      name: v.Name ?? section,
      path: v.Path,
      isRelative: v.IsRelative !== '0',
      isDefault: v.Default === '1' || installDefaults.has(v.Path),
    });
  }
  return profiles;
}

export type PrefValue = boolean | number | string;

/** Parses user_pref("name", value); / pref(...) lines. Later lines win. */
export function parsePrefs(text: string): Map<string, PrefValue> {
  const out = new Map<string, PrefValue>();
  const re = /^\s*(?:user_pref|pref)\(\s*"((?:\\.|[^"\\])*)"\s*,\s*(true|false|-?\d+|"(?:\\.|[^"\\])*")\s*\)\s*;/gm;
  for (const m of text.matchAll(re)) {
    const name = m[1];
    const raw = m[2];
    if (name === undefined || raw === undefined) continue;
    let value: PrefValue;
    if (raw === 'true') value = true;
    else if (raw === 'false') value = false;
    else if (raw.startsWith('"')) value = JSON.parse(raw) as string;
    else value = Number(raw);
    out.set(name, value);
  }
  return out;
}

function formatPrefValue(v: PrefValue): string {
  return typeof v === 'string' ? JSON.stringify(v) : String(v);
}

/**
 * Returns user.js content with `name` set to `value`: replaces existing user_pref lines for the
 * pref (all of them) or appends a new one. Everything else is preserved.
 */
export function upsertUserPref(text: string, name: string, value: PrefValue): string {
  const line = `user_pref(${JSON.stringify(name)}, ${formatPrefValue(value)});`;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^\\s*user_pref\\(\\s*"${escaped}"\\s*,[^\\n]*$`, 'gm');
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  if (re.test(text)) {
    let first = true;
    return text
      .replace(re, () => {
        if (first) {
          first = false;
          return line;
        }
        return '';
      })
      .replace(/(\r?\n){3,}/g, eol + eol);
  }
  const header = text.length === 0 ? `// Added by netfree-doctor${eol}` : '';
  const sep = text.length === 0 || text.endsWith('\n') ? '' : eol;
  return `${text}${sep}${header}${line}${eol}`;
}

export const ENTERPRISE_ROOTS_PREF = 'security.enterprise_roots.enabled';

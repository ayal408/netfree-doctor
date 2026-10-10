/**
 * Parsing of Netfree block pages.
 *
 * When Netfree blocks a request it answers with HTTP 418 ("Blocked by NetFree") and a tiny HTML
 * page containing:
 *   <iframe src="//netfree.link/block/#%7B%22block%22:%22deny%22%2C%22page_info%22:...%7D">
 * The fragment is URL-encoded JSON: {"block":"<reason>","page_info":{"url":"..."}}
 */

export interface BlockInfo {
  /** Raw block reason, e.g. "deny", "unknown", "special-site", "risk-type". */
  reason: string;
  /** The blocked URL as reported by Netfree, when present. */
  blockedUrl?: string;
  /** Full decoded JSON payload. */
  payload: Record<string, unknown>;
  /** A link the user can open to see Netfree's own block page (with the request form). */
  blockPageUrl: string;
}

const BLOCK_FRAGMENT_RE = /netfree\.link\/block\/#([^"'\s<>]+)/i;

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

/** True if the response looks like a Netfree block (status 418 and/or block iframe). */
export function looksLikeBlock(status: number | undefined, body: string | undefined): boolean {
  if (body && BLOCK_FRAGMENT_RE.test(body)) return true;
  return status === 418;
}

/** Extracts the block payload from a block page body. Returns null if none is found. */
export function parseBlockPage(body: string): BlockInfo | null {
  const m = BLOCK_FRAGMENT_RE.exec(body);
  if (!m || !m[1]) return null;
  const fragment = decodeHtmlEntities(m[1]);
  const decoded = safeDecode(fragment);
  let payload: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(decoded);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    payload = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  const reason = typeof payload.block === 'string' ? payload.block : 'unknown-format';
  const pageInfo = payload.page_info;
  let blockedUrl: string | undefined;
  if (pageInfo && typeof pageInfo === 'object' && typeof (pageInfo as Record<string, unknown>).url === 'string') {
    blockedUrl = (pageInfo as Record<string, string>).url;
  }
  return {
    reason,
    payload,
    ...(blockedUrl !== undefined ? { blockedUrl } : {}),
    blockPageUrl: `https://netfree.link/block/#${fragment}`,
  };
}

export interface ReasonExplanation {
  known: boolean;
  he: string;
  en: string;
}

/**
 * Known block reasons (all of these were observed in real 418 responses).
 * Unknown reasons are returned raw so that nothing is hidden from the user.
 */
const REASONS: Record<string, { he: string; en: string }> = {
  deny: {
    he: 'האתר נבדק ונחסם על ידי נטפרי (חסימה קבועה של האתר או של הכתובת הזו).',
    en: 'The site was reviewed and is blocked by Netfree (a permanent block of the site or this address).',
  },
  unknown: {
    he: 'האתר עדיין לא נבדק על ידי צוות נטפרי ולכן הוא חסום עד לבדיקה. אפשר לשלוח בקשת פתיחה מדף החסימה.',
    en: 'The site has not been reviewed by Netfree yet, so it is blocked until reviewed. You can request a review from the block page.',
  },
  'special-site': {
    he: 'זהו אתר שנטפרי מטפלת בו באופן מיוחד (למשל יוטיוב), והגישה אליו תלויה בהגדרות/במסלול של המנוי.',
    en: 'This is a site Netfree handles specially (e.g. YouTube); access depends on your account settings/plan.',
  },
  'risk-type': {
    he: 'סוג הבקשה או התוכן מסווג כמסוכן/לא מסונן (למשל קריאת API, הורדת קובץ או תוכן שאי אפשר לסנן), ולכן נחסם.',
    en: 'The request/content type is classified as risky or unfilterable (e.g. an API call, a download or content that cannot be filtered), so it was blocked.',
  },
};

export function explainBlockReason(reason: string): ReasonExplanation {
  const r = REASONS[reason];
  if (r) return { known: true, ...r };
  return {
    known: false,
    he: `סיבת חסימה לא מוכרת לכלי: "${reason}". פתחו את דף החסימה לפרטים.`,
    en: `Block reason not known to this tool: "${reason}". Open the block page for details.`,
  };
}

export const KNOWN_BLOCK_REASONS = Object.keys(REASONS);

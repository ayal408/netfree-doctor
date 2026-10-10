import type { CheckOutcome, Ctx, HttpResult, Status } from './types.js';
import { explainBlockReason, looksLikeBlock, parseBlockPage, type BlockInfo, type ReasonExplanation } from './parsers/blockPage.js';
import { parseInjectedNotes, type InjectionInfo } from './parsers/notes.js';
import { findNetfreeInChain } from './parsers/certs.js';

export interface UrlDiagnosis {
  url: string;
  status: Status;
  summaryHe: string;
  summaryEn: string;
  steps: CheckOutcome[];
  block?: BlockInfo & { explanation: ReasonExplanation };
  injection?: InjectionInfo;
}

type Step = Omit<CheckOutcome, 'durationMs'> & { durationMs?: number };

const RANK: Record<Status, number> = { ok: 0, info: 1, warn: 2, fail: 3 };

export function worstStatus(statuses: Status[]): Status {
  return statuses.reduce<Status>((a, b) => (RANK[b] > RANK[a] ? b : a), 'ok');
}

export function normalizeUrl(input: string): URL | null {
  const s = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  try {
    const u = new URL(withScheme);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return null;
    return u;
  } catch {
    return null;
  }
}

function blockStep(id: string, titleHe: string, titleEn: string, block: BlockInfo, ex: ReasonExplanation): Step {
  return {
    id,
    titleHe,
    titleEn,
    status: 'fail',
    summaryHe: `נחסם על ידי נטפרי (סיבה: ${block.reason}). ${ex.he}`,
    summaryEn: `Blocked by Netfree (reason: ${block.reason}). ${ex.en}`,
    detailsHe: [
      ...(block.blockedUrl ? [`כתובת חסומה: ${block.blockedUrl}`] : []),
      `דף החסימה של נטפרי (אפשר לשלוח ממנו בקשה לבדיקה/פתיחה): ${block.blockPageUrl}`,
    ],
    detailsEn: [...(block.blockedUrl ? [`Blocked URL: ${block.blockedUrl}`] : []), `Netfree block page (you can request a review there): ${block.blockPageUrl}`],
    data: { reason: block.reason, payload: block.payload },
  };
}

function httpStep(res: HttpResult): { step: Step; block?: BlockInfo; injection?: InjectionInfo } {
  if (!res.ok || res.status === undefined) {
    return {
      step: {
        id: 'http',
        titleHe: 'בקשת HTTP',
        titleEn: 'HTTP request',
        status: 'fail',
        summaryHe: `הבקשה נכשלה: ${res.error ?? 'שגיאה לא ידועה'}`,
        summaryEn: `Request failed: ${res.error ?? 'unknown error'}`,
      },
    };
  }
  const body = res.body ?? '';
  if (looksLikeBlock(res.status, body)) {
    const block = parseBlockPage(body);
    if (block) {
      return { step: blockStep('http', 'בקשת HTTP', 'HTTP request', block, explainBlockReason(block.reason)), block };
    }
    return {
      step: {
        id: 'http',
        titleHe: 'בקשת HTTP',
        titleEn: 'HTTP request',
        status: 'fail',
        summaryHe: `התקבל קוד 418 (${res.statusText ?? ''}): כנראה חסימה של נטפרי, אבל לא הצלחנו לקרוא את הסיבה.`,
        summaryEn: `Got HTTP 418 (${res.statusText ?? ''}): probably a Netfree block, but the reason could not be parsed.`,
      },
    };
  }
  const injection = parseInjectedNotes(body);
  const loc = res.headers?.location;
  const base: Step = {
    id: 'http',
    titleHe: 'בקשת HTTP',
    titleEn: 'HTTP request',
    status: res.status < 400 ? 'ok' : 'warn',
    summaryHe:
      res.status < 400
        ? `השרת ענה ${res.status}${loc ? ` (הפניה אל ${loc})` : ''} — לא נחסם.`
        : `השרת ענה ${res.status}. זו תשובה של האתר עצמו ולא חסימה של נטפרי.`,
    summaryEn:
      res.status < 400
        ? `Server answered ${res.status}${loc ? ` (redirect to ${loc})` : ''} — not blocked.`
        : `Server answered ${res.status}. This is the site's own answer, not a Netfree block.`,
    data: { status: res.status, ms: res.ms },
  };
  return { step: base, injection };
}

function injectionStep(inj: InjectionInfo): Step | null {
  if (inj.notes.length === 0 && inj.scripts.length === 0) return null;
  const detailsHe: string[] = [];
  const detailsEn: string[] = [];
  for (const n of inj.notes) {
    if (n.he) detailsHe.push(`הערה: ${n.he}`);
    if (n.en) detailsEn.push(`Note: ${n.en}`);
  }
  if (inj.scripts.length) {
    detailsHe.push(`סקריפטים שנטפרי הוסיפה לדף: ${inj.scripts.join(', ')}`);
    detailsEn.push(`Scripts injected by Netfree: ${inj.scripts.join(', ')}`);
  }
  const hasNotes = inj.notes.length > 0;
  return {
    id: 'notes',
    titleHe: 'הערות של נטפרי באתר',
    titleEn: 'Netfree notes on the site',
    status: hasNotes ? 'warn' : 'info',
    summaryHe: hasNotes
      ? 'נטפרי מצרפת לאתר הזה הערה: ייתכן שחלקים ממנו (למשל תמונות) לא יעבדו בלי שינוי הגדרות סינון.'
      : 'נטפרי מוסיפה סקריפטים לדף (רגיל באתרים מסוננים).',
    summaryEn: hasNotes
      ? 'Netfree attaches a note to this site: parts of it (e.g. images) may not work without changing filter settings.'
      : 'Netfree injects scripts into the page (normal for filtered sites).',
    detailsHe,
    detailsEn,
    data: { notes: inj.notes, scripts: inj.scripts },
  };
}

/** Diagnoses a single URL: DNS → TCP → TLS → HTTP (and WebSocket upgrade for ws/wss). */
export async function diagnoseUrl(ctx: Ctx, input: string): Promise<UrlDiagnosis> {
  const steps: Step[] = [];
  const u = normalizeUrl(input);
  if (!u) {
    return {
      url: input,
      status: 'fail',
      summaryHe: 'כתובת לא תקינה. דוגמה: https://example.com',
      summaryEn: 'Invalid URL. Example: https://example.com',
      steps: [],
    };
  }
  const secure = u.protocol === 'https:' || u.protocol === 'wss:';
  const isWs = u.protocol === 'ws:' || u.protocol === 'wss:';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const port = u.port ? Number(u.port) : secure ? 443 : 80;
  let block: (BlockInfo & { explanation: ReasonExplanation }) | undefined;
  let injection: InjectionInfo | undefined;

  const finish = (): UrlDiagnosis => {
    const outSteps = steps.map((s) => ({ durationMs: 0, ...s }));
    const status = worstStatus(outSteps.map((s) => s.status));
    let summaryHe: string;
    let summaryEn: string;
    if (block) {
      summaryHe = `הכתובת חסומה על ידי נטפרי (${block.reason}).`;
      summaryEn = `The URL is blocked by Netfree (${block.reason}).`;
    } else if (status === 'fail') {
      const f = outSteps.find((s) => s.status === 'fail')!;
      summaryHe = `נכשל בשלב: ${f.titleHe}.`;
      summaryEn = `Failed at: ${f.titleEn}.`;
    } else if (status === 'warn') {
      summaryHe = 'הכתובת נגישה, אבל יש הערות שכדאי לקרוא.';
      summaryEn = 'Reachable, with notes worth reading.';
    } else {
      summaryHe = 'הכתובת נגישה ולא נחסמה.';
      summaryEn = 'Reachable and not blocked.';
    }
    return { url: u.toString(), status, summaryHe, summaryEn, steps: outSteps, ...(block ? { block } : {}), ...(injection ? { injection } : {}) };
  };

  // DNS
  const dns = await ctx.dnsLookup(host);
  if (dns.error || dns.addresses.length === 0) {
    steps.push({ id: 'dns', titleHe: 'DNS', titleEn: 'DNS', status: 'fail', summaryHe: `השם ${host} לא נמצא ב-DNS (${dns.error ?? 'אין כתובות'}).`, summaryEn: `${host} did not resolve (${dns.error ?? 'no addresses'}).` });
    return finish();
  }
  steps.push({ id: 'dns', titleHe: 'DNS', titleEn: 'DNS', status: 'ok', summaryHe: `${host} → ${dns.addresses.slice(0, 3).join(', ')}`, summaryEn: `${host} → ${dns.addresses.slice(0, 3).join(', ')}` });

  // TCP
  const tcp = await ctx.tcpConnect(host, port);
  if (!tcp.ok) {
    steps.push({ id: 'tcp', titleHe: 'חיבור TCP', titleEn: 'TCP connect', status: 'fail', summaryHe: `אין חיבור לפורט ${port} (${tcp.error ?? ''}).`, summaryEn: `Cannot connect to port ${port} (${tcp.error ?? ''}).` });
    return finish();
  }
  steps.push({ id: 'tcp', titleHe: 'חיבור TCP', titleEn: 'TCP connect', status: 'ok', summaryHe: `פורט ${port} פתוח (${tcp.ms ?? '?'}ms).`, summaryEn: `Port ${port} open (${tcp.ms ?? '?'}ms).` });

  // TLS
  if (secure) {
    const tls = await ctx.tlsProbe(host, port);
    if (!tls.ok) {
      steps.push({ id: 'tls', titleHe: 'הצפנה (TLS)', titleEn: 'TLS', status: 'fail', summaryHe: `לחיצת היד המוצפנת נכשלה: ${tls.error ?? ''}`, summaryEn: `TLS handshake failed: ${tls.error ?? ''}` });
      return finish();
    }
    const leaf = tls.chain[0];
    const issuer = leaf ? [leaf.issuer.O, leaf.issuer.CN].filter(Boolean).join(' / ') : '?';
    const viaNetfree = findNetfreeInChain(tls.chain) >= 0;
    const authNote = tls.authorized
      ? { he: 'Node סומך על התעודה.', en: 'Node trusts the certificate.' }
      : { he: `Node לא סומך על התעודה (${tls.authorizationError ?? ''}) — ראו את בדיקת Node/npm.`, en: `Node does not trust the certificate (${tls.authorizationError ?? ''}) — see the Node/npm check.` };
    steps.push({
      id: 'tls',
      titleHe: 'הצפנה (TLS)',
      titleEn: 'TLS',
      status: tls.authorized ? 'ok' : viaNetfree ? 'warn' : 'fail',
      summaryHe: `${viaNetfree ? 'התעודה הונפקה על ידי נטפרי' : 'תעודה מקורית (לא דרך נטפרי)'}: ${issuer}. ${authNote.he}`,
      summaryEn: `${viaNetfree ? 'Certificate issued by Netfree' : 'Original certificate (not via Netfree)'}: ${issuer}. ${authNote.en}`,
      data: { viaNetfree, issuer: leaf?.issuer ?? null, authorized: tls.authorized },
    });
  }

  // HTTP (for ws/wss the equivalent http/https URL)
  const httpUrl = new URL(u.toString());
  if (isWs) httpUrl.protocol = secure ? 'https:' : 'http:';
  const http = await ctx.httpGet(httpUrl.toString());
  const h = httpStep(http);
  steps.push(h.step);
  if (h.block) block = { ...h.block, explanation: explainBlockReason(h.block.reason) };
  if (h.injection) {
    injection = h.injection;
    const inj = injectionStep(h.injection);
    if (inj) steps.push(inj);
  }

  // WebSocket upgrade
  if (isWs) {
    const ws = await ctx.wsHandshake(u.toString());
    const wsBlock = ws.body && looksLikeBlock(ws.status, ws.body) ? parseBlockPage(ws.body) : null;
    if (ws.upgraded) {
      steps.push({ id: 'websocket', titleHe: 'WebSocket', titleEn: 'WebSocket', status: 'ok', summaryHe: 'שדרוג ל-WebSocket הצליח (101).', summaryEn: 'WebSocket upgrade succeeded (101).' });
    } else if (wsBlock) {
      const ex = explainBlockReason(wsBlock.reason);
      block = block ?? { ...wsBlock, explanation: ex };
      steps.push(blockStep('websocket', 'WebSocket', 'WebSocket', wsBlock, ex));
    } else if (ws.status === 418) {
      steps.push({ id: 'websocket', titleHe: 'WebSocket', titleEn: 'WebSocket', status: 'fail', summaryHe: 'שדרוג ל-WebSocket נחסם (418) על ידי נטפרי.', summaryEn: 'WebSocket upgrade blocked (418) by Netfree.' });
    } else {
      steps.push({
        id: 'websocket',
        titleHe: 'WebSocket',
        titleEn: 'WebSocket',
        status: ws.status ? 'warn' : 'fail',
        summaryHe: ws.status ? `השרת לא שדרג ל-WebSocket (קוד ${ws.status}); ייתכן שהשרת דורש פרמטרים/התחברות.` : `שדרוג ל-WebSocket נכשל: ${ws.error ?? ''}`,
        summaryEn: ws.status ? `Server did not upgrade (status ${ws.status}); it may require parameters/auth.` : `WebSocket upgrade failed: ${ws.error ?? ''}`,
      });
    }
  }
  return finish();
}

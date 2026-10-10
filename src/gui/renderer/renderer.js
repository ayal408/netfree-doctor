// Renderer: builds result cards with DOM APIs only (no innerHTML with data).
'use strict';

(function () {
  const api = window.doctor;
  const $ = (id) => document.getElementById(id);
  const STATUS_HE = { ok: 'תקין', warn: 'אזהרה', fail: 'תקלה', info: 'לידיעה' };
  const URL_RE = /(https:\/\/[^\s)]+)/g;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  /** Appends text to a parent, turning https:// URLs into links opened in the browser. */
  function appendLinkified(parent, text) {
    let last = 0;
    for (const m of text.matchAll(URL_RE)) {
      if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
      const a = el('a', 'ltr', m[1]);
      a.href = '#';
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        api.openExternal(m[1]);
      });
      parent.appendChild(a);
      last = m.index + m[1].length;
    }
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }

  function card(r) {
    const c = el('article', 'card ' + r.status);
    c.dataset.id = r.id;
    const head = el('div', 'card-head');
    head.appendChild(el('span', 'badge', STATUS_HE[r.status] || r.status));
    head.appendChild(el('h3', '', r.titleHe));
    if (r.fix) {
      const b = el('button', 'fix-btn', 'תקן');
      b.title = r.fix.titleHe;
      b.addEventListener('click', () => openFix(r.fix.id));
      head.appendChild(b);
    }
    c.appendChild(head);
    const p = el('p');
    appendLinkified(p, r.summaryHe);
    c.appendChild(p);
    if (r.detailsHe && r.detailsHe.length) {
      const d = el('details');
      if (r.status === 'fail' || r.status === 'warn') d.open = true;
      d.appendChild(el('summary', '', 'פרטים'));
      const ul = el('ul');
      for (const line of r.detailsHe) {
        const li = el('li');
        appendLinkified(li, line);
        ul.appendChild(li);
      }
      d.appendChild(ul);
      c.appendChild(d);
    }
    return c;
  }

  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => (t.hidden = true), 6000);
  }

  async function runChecks() {
    const btn = $('run');
    btn.disabled = true;
    btn.textContent = 'בודק...';
    const results = $('results');
    results.textContent = '';
    $('summary').hidden = true;
    const pending = el('article', 'card pending', 'מריץ בדיקות... (זה לוקח כמה שניות)');
    results.appendChild(pending);
    api.onCheckResult((r) => {
      pending.remove();
      results.appendChild(card(r));
    });
    try {
      const all = await api.runChecks();
      results.textContent = '';
      for (const r of all) results.appendChild(card(r));
      const count = { ok: 0, warn: 0, fail: 0, info: 0 };
      for (const r of all) count[r.status]++;
      const s = $('summary');
      s.textContent = `סיכום: ${count.ok} תקין · ${count.warn} אזהרות · ${count.fail} תקלות · ${count.info} לידיעה`;
      s.hidden = false;
    } catch (e) {
      results.textContent = '';
      results.appendChild(el('p', 'blocker', 'שגיאה בהרצת הבדיקות: ' + (e && e.message ? e.message : e)));
    } finally {
      btn.disabled = false;
      btn.textContent = 'הפעל בדיקה שוב';
    }
  }

  async function checkUrl(ev) {
    ev.preventDefault();
    const url = $('url').value.trim();
    if (!url) return;
    const out = $('url-result');
    out.textContent = '';
    out.appendChild(el('p', 'muted', 'בודק את ' + url + '...'));
    const d = await api.checkUrl(url);
    out.textContent = '';
    const head = { id: 'url', status: d.status, titleHe: d.url, summaryHe: d.summaryHe, detailsHe: [] };
    for (const s of d.steps) {
      head.detailsHe.push(`${STATUS_HE[s.status]} · ${s.titleHe}: ${s.summaryHe}`);
      for (const line of s.detailsHe || []) head.detailsHe.push('   ' + line);
    }
    if (d.block) head.detailsHe.push('הסבר: ' + d.block.explanation.he);
    const c = card(head);
    c.querySelector('h3').classList.add('ltr');
    out.appendChild(c);
  }

  let currentFix = null;

  async function openFix(id) {
    const plan = await api.planFix(id);
    if (plan.error) return toast(plan.error);
    currentFix = id;
    $('modal-title').textContent = plan.title;
    const note = $('modal-note');
    note.hidden = !plan.note;
    note.textContent = plan.note || '';
    const ol = $('modal-lines');
    ol.textContent = '';
    for (const line of plan.lines) {
      const li = el('li', 'ltr-mixed');
      appendLinkified(li, line.replace(/^\d+\.\s*/, ''));
      ol.appendChild(li);
    }
    const blocker = $('modal-blocker');
    const reasons = [plan.blocker, ...(plan.violations || [])].filter(Boolean);
    blocker.hidden = reasons.length === 0;
    blocker.textContent = reasons.length ? 'לא ניתן לבצע כעת: ' + reasons.join('; ') : '';
    $('modal-apply').disabled = reasons.length > 0;
    $('modal').hidden = false;
  }

  function closeModal() {
    $('modal').hidden = true;
    currentFix = null;
  }

  async function applyFix() {
    if (!currentFix) return;
    const btn = $('modal-apply');
    btn.disabled = true;
    const r = await api.applyFix(currentFix);
    btn.disabled = false;
    closeModal();
    if (r.ok) {
      toast('התיקון בוצע. אפשר לבטל עם "ביטול התיקון האחרון". בודק שוב...');
      runChecks();
    } else {
      toast('התיקון לא בוצע: ' + r.error);
    }
  }

  async function undoLast() {
    if (!window.confirm('לבטל את התיקון האחרון שבוצע?')) return;
    const r = await api.undoLast();
    if (r.ok) {
      toast('התיקון ' + r.fixId + ' בוטל.');
      runChecks();
    } else toast(r.error || 'הביטול נכשל: ' + (r.errors || []).join('; '));
  }

  $('run').addEventListener('click', runChecks);
  $('url-form').addEventListener('submit', checkUrl);
  $('modal-cancel').addEventListener('click', closeModal);
  $('modal-apply').addEventListener('click', applyFix);
  $('undo').addEventListener('click', undoLast);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });
})();

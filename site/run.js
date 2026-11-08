// Renders /latest-run.json and /history.json, which the live runner (runner/main.py) writes
// every 15 minutes. latest-run.json is a Report as site/report.schema.json states it
// (runner/report.py); a report of another format is not rendered, and one the page can't
// render says so. tests/site/render.test.mjs renders the report the runner's test publishes.
// Plain DOM: every value from the report goes in through textContent.
(function () {
  'use strict';

  // The report format this page reads (runner/report.py FORMAT).
  const FORMAT = 3;
  const SIGNATURE_FIELDS = new Set(['signature', 'signature-input', 'signature-agent', 'content-digest']);
  // The step groups (runner/report.py Group), in the order a run takes them.
  const GROUPS = {
    directory: 'Key directories',
    signature: 'With a Web Bot Auth signature',
    bearer: 'With a bearer token',
    cloudflare: 'Interop with Cloudflare’s library',
    publish: 'Publishing the report',
  };

  // ── Building blocks ──────────────────────────────────────────────────────

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else node.setAttribute(key, value);
    }
    for (const child of children.flat()) {
      if (child == null) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function ago(iso) {
    const seconds = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (!Number.isFinite(seconds)) return '';
    if (seconds < 90) return `${seconds} s ago`;
    if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
    return `${Math.round(seconds / 3600)} h ago`;
  }

  function code(text) { return el('code', { text }); }

  /** A two-column table of facts; a null row is left out. */
  function factsTable(rows) {
    const table = el('table', {}, el('tbody', {}, rows.filter(Boolean).map(([k, v]) =>
      el('tr', {}, el('th', { text: k }), el('td', {}, v)))));
    return el('div', { class: 'table-wrap' }, table);
  }

  function headerBlock(start, headers, note) {
    const pre = el('pre', { class: 'headers' }, el('span', { text: start + '\n' }));
    for (const [name, value] of headers.lines) {
      pre.append(el('span', { class: SIGNATURE_FIELDS.has(name) ? 'sig' : '' },
        el('span', { class: 'name', text: name }), ': ' + value), '\n');
    }
    const withheld = headers.withheld.length ? `Withheld from this report: ${headers.withheld.join(', ')}. ` : '';
    return [pre, withheld || note ? el('p', { class: 'note' }, withheld, note) : null];
  }

  function bodyBlock(label, body) {
    if (body == null || body === '') return null;
    return el('details', {}, el('summary', { text: label }),
      el('div', {}, el('pre', { text: typeof body === 'string' ? body : JSON.stringify(body, null, 2) })));
  }

  /** A message as a party sent, kept, or received it: its heading, header lines, and body. */
  function messageSection(heading, start, message, note, bodyLabel) {
    return [el('h3', { text: heading }), ...headerBlock(start, message.headers, note),
      bodyLabel ? bodyBlock(bodyLabel, message.body) : null];
  }

  function directoryBlock(title, directory, fetchedAt) {
    if (!directory) return null;
    const kids = directory.keys.map(k => k.kid).join(', ');
    const at = fetchedAt ?? directory.fetched_at;
    return el('details', {}, el('summary', { text: title }), el('div', {},
      el('p', {}, 'Fetched ', code(directory.url), at ? ` at ${at}` : '', `. Keys: ${kids || 'none'}.`),
      headerBlock(`HTTP ${directory.status}`, directory.headers),
      bodyBlock('Keys (public JWKs)', { keys: directory.keys })));
  }

  // ── The sections ─────────────────────────────────────────────────────────

  function summary(run) {
    const ok = run.ok === true;
    const software = run.software;
    return el('div', { class: 'run-summary' },
      el('span', { class: `verdict ${ok ? 'ok' : 'bad'}`, text: ok ? 'Pass' : 'Fail' }),
      el('span', { class: 'meta', text: `Started ${run.started_at} (${ago(run.started_at)}), ${run.duration_ms ?? '?'} ms in all` }),
      software ? el('span', { class: 'meta',
        text: `iab-agentic-primitives ${software.iab_agentic_primitives}, openproposal-sdk ${software.openproposal_sdk}` }) : null);
  }

  function historyStrip(history) {
    if (!history.length) return [];
    const passed = history.filter(r => r.ok).length;
    return [el('p', { class: 'note', text: `The last ${history.length} runs, newest first:` }),
      el('div', { class: 'history', role: 'img', 'aria-label': `${passed} of ${history.length} runs passed` },
        history.map(r => el('span', { class: r.ok ? '' : 'bad', title: `${r.started_at}: ${r.ok ? 'pass' : 'fail ' + r.failed.join(', ')}` })))];
  }

  function stepRows(steps) {
    const rows = [];
    let group = null;
    for (const step of steps) {
      if (step.group !== group) {
        group = step.group;
        rows.push(el('tr', { class: 'group' }, el('th', { colspan: '4', text: GROUPS[group] ?? group })));
      }
      rows.push(el('tr', {},
        el('td', { class: `state ${step.ok ? 'ok' : 'bad'}`, text: step.ok ? 'Pass' : 'Fail' }),
        el('td', { text: step.title }),
        el('td', { class: 'ms', text: `${step.ms} ms` }),
        el('td', { class: 'detail', text: step.detail ?? '' })));
    }
    return rows;
  }

  function stepsTable(steps) {
    const head = el('tr', {}, ['Result', 'Step', 'Time', 'Detail'].map(text => el('th', { text })));
    return [el('h3', { text: 'Steps' }), el('div', { class: 'table-wrap' },
      el('table', { class: 'steps' }, el('thead', {}, head), el('tbody', {}, stepRows(steps))))];
  }

  function pathFacts(section) {
    const { outcome, seller, buyer, digest, reverify } = section;
    return factsTable([
      ['Proposal', code(section.proposal_id)],
      ['Seller resolved', seller ? [code(seller.principal_id), ` with ${seller.authentication_method}`] : '–'],
      ['record_digest', digest ? [code(digest.record_digest), ` on both sides, over ${digest.digest_input_bytes} bytes`] : '–'],
      ['Buyer signed with', outcome.keyid ? code(outcome.keyid) : 'nothing: a bearer token'],
      ['Seller signed with', buyer ? code(buyer.response.keyid) : '–'],
      ['Attributed (§ 4.1.2)', String(outcome.attributed)],
      reverify ? ['Verified again offline', `request and bound answer: ${reverify.response_bound ? 'bound' : 'not bound'}`] : null,
    ]);
  }

  function pathMessages(section, bearer) {
    const { seller, buyer } = section;
    const parts = [];
    if (buyer) {
      const sent = buyer.request;
      parts.push(...messageSection('The request, as the buyer sent it', `${sent.method} ${sent.url}`, sent,
        bearer ? 'The request carried the bearer token; the buyer never stores it.' : '', 'Request body: the Commit'));
    }
    if (seller && seller.request) {
      const kept = seller.request;
      parts.push(...messageSection('The same request, as the seller received and kept it', `${kept.method} ${kept.url}`,
        kept, 'Caddy adds forwarding headers; the signature doesn’t cover them.'));
    }
    if (buyer) {
      parts.push(...messageSection('The seller’s signed answer, as the buyer received it', `HTTP ${buyer.response.status}`,
        buyer.response, bearer ? 'Unbound: a bearer request carries no signature to bind to.' : '', 'Answer body: the CommitResult'));
    }
    return parts;
  }

  function pathPanel(title, section, bearer) {
    if (!section || !section.outcome) {
      return el('details', {}, el('summary', { text: `${title}: no data` }),
        el('div', {}, el('p', { class: 'note', text: 'This path failed before it produced a record. See the steps.' })));
    }
    const { seller, buyer } = section;
    return el('details', { open: '' }, el('summary', { text: title }), el('div', {},
      pathFacts(section), pathMessages(section, bearer),
      directoryBlock('The buyer’s directory, as the seller fetched it', seller && seller.directory),
      directoryBlock('The seller’s directory, as the buyer fetched it', buyer && buyer.directory)));
  }

  function pathsSection(run) {
    return [el('h3', { text: 'What each party saw' }),
      pathPanel(GROUPS.signature, run.signature, false),
      pathPanel(GROUPS.bearer, run.bearer, true)];
  }

  function directoriesSection(run) {
    const directories = Object.entries(run.directories ?? {}).filter(([, d]) => d);
    if (!directories.length) return null;
    return el('details', {}, el('summary', { text: 'Key directories, as the runner fetched and verified them' }),
      el('div', {}, directories.map(([party, d]) =>
        directoryBlock(`${party}: valid until ${d.expires}`, d, run.started_at))));
  }

  function cloudflareSection(run) {
    if (!run.cloudflare) return null;
    return el('details', {}, el('summary', { text: 'Cloudflare’s verifier on the buyer’s signature' }),
      el('div', {}, el('pre', { text: JSON.stringify(run.cloudflare.verdict, null, 2) })));
  }

  function render(run, history) {
    const root = document.getElementById('run');
    root.textContent = '';
    root.append(summary(run), ...historyStrip(history), ...stepsTable(run.steps), ...pathsSection(run));
    for (const section of [directoriesSection(run), cloudflareSection(run)]) {
      if (section) root.append(section);
    }
  }

  // ── Loading ──────────────────────────────────────────────────────────────

  function setStatus(state, text) {
    const pill = document.getElementById('run-status');
    if (!pill) return;
    pill.classList.remove('ok', 'bad');
    if (state) pill.classList.add(state);
    pill.lastElementChild.textContent = text;
  }

  function showEmpty(status, text) {
    setStatus(null, status);
    const root = document.getElementById('run');
    root.textContent = '';
    root.append(el('p', { class: 'empty', text }));
  }

  async function load(path) {
    const response = await fetch(path, { cache: 'no-store' });
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    return response.json();
  }

  async function main() {
    let run;
    try {
      run = await load('latest-run.json');
    } catch (e) {
      return showEmpty('No run report yet', `No run report is available yet (${e.message}). The runner writes one every 15 minutes.`);
    }
    if (run.format !== FORMAT) {
      return showEmpty('Unsupported run report', `The run report has format ${run.format}; this page reads format ${FORMAT}.`);
    }
    let history = [];
    try { history = (await load('history.json')).runs ?? []; } catch { /* the summary works without it */ }
    try {
      render(run, history);
    } catch (e) {
      return showEmpty('Unreadable run report', `The run report can't be rendered: ${e.message}`);
    }
    return setStatus(run.ok ? 'ok' : 'bad', `Latest run ${run.ok ? 'passed' : 'failed'}, ${ago(run.started_at)}`);
  }

  main();
})();

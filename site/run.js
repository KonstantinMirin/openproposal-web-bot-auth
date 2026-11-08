// Renders /latest-run.json and /history.json, which the live runner (runner/main.py) writes
// every 15 minutes. latest-run.json is a Report as site/report.schema.json states it
// (runner/report.py); a report of another format is not rendered.
// Plain DOM: every value from the report goes in through textContent.
(function () {
  'use strict';

  // The report format this page reads (runner/report.py FORMAT).
  const FORMAT = 3;
  const SIGNATURE_FIELDS = new Set(['signature', 'signature-input', 'signature-agent', 'content-digest']);

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

  function headerBlock(start, headers, note) {
    const pre = el('pre', { class: 'headers' });
    if (start) pre.append(el('span', { text: start + '\n' }));
    for (const [name, value] of headers.lines || []) {
      const line = el('span', { class: SIGNATURE_FIELDS.has(name) ? 'sig' : '' },
        el('span', { class: 'name', text: name }), ': ' + value);
      pre.append(line, '\n');
    }
    const withheld = headers.withheld || [];
    const parts = [pre];
    if (withheld.length || note) {
      parts.push(el('p', { class: 'note' },
        withheld.length ? `Withheld from this report: ${withheld.join(', ')}. ` : '', note || ''));
    }
    return parts;
  }

  function bodyBlock(label, body) {
    if (body == null || body === '') return null;
    return el('details', {}, el('summary', { text: label }),
      el('div', {}, el('pre', { text: typeof body === 'string' ? body : JSON.stringify(body, null, 2) })));
  }

  function directoryBlock(title, directory) {
    if (!directory) return null;
    const kids = (directory.keys || []).map(k => k.kid).join(', ');
    return el('details', {}, el('summary', { text: title }), el('div', {},
      el('p', {}, 'Fetched ', code(directory.url), directory.fetched_at ? ` at ${directory.fetched_at}` : '',
        `. Keys: ${kids || 'none'}.`),
      headerBlock(`HTTP ${directory.status}`, directory.headers),
      bodyBlock('Keys (public JWKs)', { keys: directory.keys })));
  }

  function facts(rows) {
    const table = el('table', {}, el('tbody', {}, rows.filter(Boolean).map(([k, v]) =>
      el('tr', {}, el('th', { text: k }), el('td', {}, v)))));
    return el('div', { class: 'table-wrap' }, table);
  }

  function pathPanel(title, section, credential) {
    if (!section || !section.outcome) {
      return el('details', {}, el('summary', { text: `${title}: no data` }),
        el('div', {}, el('p', { class: 'note', text: 'This path failed before it produced a record. See the steps.' })));
    }
    const { outcome, seller, buyer, digest, reverify } = section;
    const sent = buyer && buyer.request;
    const answer = buyer && buyer.response;
    const parts = [
      facts([
        ['Proposal', code(section.proposal_id)],
        ['Seller resolved', seller ? [code(seller.principal_id), ` with ${seller.authentication_method}`] : '–'],
        ['record_digest', digest ? [code(digest.record_digest), ` on both sides, over ${digest.digest_input_bytes} bytes`] : '–'],
        ['Buyer signed with', outcome.keyid ? code(outcome.keyid) : 'nothing: a bearer token'],
        ['Seller signed with', answer ? code(answer.keyid) : '–'],
        ['Attributed (§ 4.1.2)', String(Boolean(outcome.attributed))],
        reverify ? ['Verified again offline', `request and bound answer: ${reverify.response_bound ? 'bound' : 'not bound'}`] : null,
      ]),
    ];
    if (sent) {
      parts.push(el('h3', { text: 'The request, as the buyer sent it' }),
        ...headerBlock(`${sent.method} ${sent.url}`, sent.headers,
          credential === 'bearer' ? 'The request carried the bearer token; the buyer never stores it.' : ''),
        bodyBlock('Request body: the Commit', sent.body));
    }
    if (seller && seller.request) {
      parts.push(el('h3', { text: 'The same request, as the seller received and kept it' }),
        ...headerBlock(`${seller.request.method} ${seller.request.url}`, seller.request.headers,
          'Caddy adds forwarding headers; the signature doesn’t cover them.'));
    }
    if (answer) {
      parts.push(el('h3', { text: 'The seller’s signed answer, as the buyer received it' }),
        ...headerBlock(`HTTP ${answer.status}`, answer.headers,
          credential === 'bearer' ? 'Unbound: a bearer request carries no signature to bind to.' : ''),
        bodyBlock('Answer body: the CommitResult', answer.body));
    }
    parts.push(directoryBlock('The buyer’s directory, as the seller fetched it', seller && seller.directory),
      directoryBlock('The seller’s directory, as the buyer fetched it', buyer && buyer.directory));
    return el('details', { open: '' }, el('summary', { text: title }), el('div', {}, parts));
  }

  function render(run, history) {
    const root = document.getElementById('run');
    root.textContent = '';
    const ok = run.ok === true;
    root.append(el('div', { class: 'run-summary' },
      el('span', { class: `verdict ${ok ? 'ok' : 'bad'}`, text: ok ? 'Pass' : 'Fail' }),
      el('span', { class: 'meta', text: `Started ${run.started_at} (${ago(run.started_at)}), ${run.duration_ms ?? '?'} ms in all` }),
      run.software ? el('span', { class: 'meta', text: `iab-agentic-primitives ${run.software.iab_agentic_primitives}, openproposal-sdk ${run.software.openproposal_sdk}` }) : null));

    if (history.length) {
      root.append(el('p', { class: 'note', text: `The last ${history.length} runs, newest first:` }),
        el('div', { class: 'history', role: 'img', 'aria-label': `${history.filter(r => r.ok).length} of ${history.length} runs passed` },
          history.map(r => el('span', { class: r.ok ? '' : 'bad', title: `${r.started_at}: ${r.ok ? 'pass' : 'fail ' + r.failed.join(', ')}` }))));
    }

    const GROUPS = { directory: 'Key directories', signature: 'With a Web Bot Auth signature',
      bearer: 'With a bearer token', cloudflare: 'Interop with Cloudflare\u2019s library' };
    const rows = [];
    let group = null;
    for (const step of run.steps || []) {
      if (GROUPS[step.group] && step.group !== group) {
        group = step.group;
        rows.push(el('tr', { class: 'group' }, el('th', { colspan: '4', text: GROUPS[group] })));
      }
      rows.push(el('tr', {},
        el('td', { class: `state ${step.ok ? 'ok' : 'bad'}`, text: step.ok ? 'Pass' : 'Fail' }),
        el('td', { text: step.title }),
        el('td', { class: 'ms', text: `${step.ms} ms` }),
        el('td', { class: 'detail', text: step.detail || '' })));
    }
    root.append(el('h3', { text: 'Steps' }), el('div', { class: 'table-wrap' }, el('table', { class: 'steps' },
      el('thead', {}, el('tr', {}, el('th', { text: 'Result' }), el('th', { text: 'Step' }), el('th', { text: 'Time' }), el('th', { text: 'Detail' }))),
      el('tbody', {}, rows))));

    root.append(el('h3', { text: 'What each party saw' }),
      pathPanel('With a Web Bot Auth signature', run.signature, 'web_bot_auth'),
      pathPanel('With a bearer token', run.bearer, 'bearer'));

    const directories = Object.entries(run.directories || {}).filter(([, d]) => d);
    if (directories.length) {
      root.append(el('details', {}, el('summary', { text: 'Key directories, as the runner fetched and verified them' }),
        el('div', {}, directories.map(([party, d]) => directoryBlock(`${party}: valid until ${d.expires}`,
          { ...d, fetched_at: run.started_at })))));
    }

    const verdict = run.cloudflare && run.cloudflare.verdict;
    if (verdict) {
      root.append(el('details', {}, el('summary', { text: 'Cloudflare’s verifier on the buyer’s signature' }),
        el('div', {}, el('pre', { text: JSON.stringify(verdict, null, 2) }))));
    }
  }

  function setStatus(state, text) {
    const pill = document.getElementById('run-status');
    if (!pill) return;
    pill.classList.remove('ok', 'bad');
    if (state) pill.classList.add(state);
    pill.lastElementChild.textContent = text;
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
      setStatus(null, 'No run report yet');
      const root = document.getElementById('run');
      root.textContent = '';
      root.append(el('p', { class: 'empty', text: `No run report is available yet (${e.message}). The runner writes one every 15 minutes.` }));
      return;
    }
    if (run.format !== FORMAT) {
      setStatus(null, 'Unsupported run report');
      const root = document.getElementById('run');
      root.textContent = '';
      root.append(el('p', { class: 'empty', text: `The run report has format ${run.format}; this page reads format ${FORMAT}.` }));
      return;
    }
    let history = [];
    try { history = (await load('history.json')).runs || []; } catch (e) { /* the summary works without it */ }
    setStatus(run.ok ? 'ok' : 'bad', `Latest run ${run.ok ? 'passed' : 'failed'}, ${ago(run.started_at)}`);
    render(run, history);
  }

  main();
})();

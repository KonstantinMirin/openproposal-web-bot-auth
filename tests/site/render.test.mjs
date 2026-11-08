// site/run.js against the report the live runner publishes (node --test, run by make test).
//
// tests/test_runner.py publishes its passing run to tests/site/published/. This
// test loads run.js as the page does, in a minimal DOM whose fetch answers those
// files, and hands it the report read-only: a member run.js reads that the report
// lacks throws, so a renamed or dropped report field fails the render. run.js
// shows a report it can't render as "Unreadable run report", which fails here.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const RUN_JS = readFileSync(new URL('../../site/run.js', import.meta.url), 'utf8');
const PUBLISHED = new URL('published/', import.meta.url);

/** A file the runner's test published. */
function published(name) {
  try {
    return JSON.parse(readFileSync(new URL(name, PUBLISHED), 'utf8'));
  } catch (e) {
    throw new Error(`${name}: tests/test_runner.py publishes it; run make test (${e.message})`);
  }
}

// What the language itself probes on any object: `await` asks for `then`, and
// JSON.stringify for `toJSON`. A report holds neither, and run.js reads neither.
const PROBED = new Set(['then', 'toJSON']);

/** `value` as run.js reads it, where reading a member it lacks throws. */
function strict(value, path) {
  if (value === null || typeof value !== 'object') return value;
  return new Proxy(value, {
    get(target, key) {
      if (typeof key !== 'symbol' && !PROBED.has(key) && !Reflect.has(target, key)) {
        throw new Error(`run.js reads ${path}.${key}, which the report lacks`);
      }
      return strict(Reflect.get(target, key), `${path}.${String(key)}`);
    },
  });
}

// ── A minimal DOM: what run.js calls, and nothing else ─────────────────────

class FakeNode {}

class FakeText extends FakeNode {
  constructor(text) { super(); this.textContent = String(text); }
}

class FakeElement extends FakeNode {
  constructor(tag) {
    super();
    Object.assign(this, { tag, children: [], attributes: {}, className: '', classes: new Set() });
    this.classList = { add: c => this.classes.add(c), remove: (...c) => c.forEach(x => this.classes.delete(x)) };
  }

  setAttribute(name, value) { this.attributes[name] = String(value); }
  append(...nodes) { this.children.push(...nodes.map(n => (n instanceof FakeNode ? n : new FakeText(n)))); }
  get lastElementChild() { return this.children.filter(c => c instanceof FakeElement).at(-1) ?? null; }
  get textContent() { return this.children.map(c => c.textContent).join(''); }
  set textContent(text) { this.children = text === '' ? [] : [new FakeText(text)]; }

  /** Every element below this one with the tag `tag`. */
  all(tag) {
    const below = this.children.filter(c => c instanceof FakeElement);
    return below.flatMap(c => [...(c.tag === tag ? [c] : []), ...c.all(tag)]);
  }
}

/** The page's two anchors, and a DOM and fetch over the published files. */
function page(files) {
  const status = new FakeElement('a');
  status.append(new FakeElement('span'), new FakeElement('span'));
  const elements = { run: new FakeElement('div'), 'run-status': status };
  const document = {
    createElement: tag => new FakeElement(tag),
    createTextNode: text => new FakeText(text),
    getElementById: id => elements[id] ?? null,
  };
  const fetch = async path => (path in files
    ? { ok: true, status: 200, json: async () => strict(files[path], path) }
    : { ok: false, status: 404 });
  return { elements, context: vm.createContext({ document, fetch, Node: FakeNode }) };
}

/** Renders the files with run.js, as the page loads it, once its fetches have settled. */
async function render(files) {
  const { elements, context } = page(files);
  vm.runInContext(RUN_JS, context, { filename: 'site/run.js' });
  for (let i = 0; i < 5; i += 1) await new Promise(resolve => setImmediate(resolve));
  return { root: elements.run, status: elements['run-status'].lastElementChild.textContent };
}

test('run.js renders every section of the published report', async () => {
  const report = published('latest-run.json');
  const history = published('history.json');
  const { root, status } = await render({ 'latest-run.json': report, 'history.json': history });
  const text = root.textContent;

  assert.match(status, /^Latest run passed/, text);
  const titles = root.all('td').map(td => td.textContent);
  for (const step of report.steps) assert.ok(titles.includes(step.title), step.title);
  assert.ok(text.includes(report.signature.digest.record_digest));
  assert.ok(text.includes(report.bearer.outcome.proposal_id));
  assert.ok(text.includes(report.directories.cfbot.url));
  assert.ok(text.includes(report.cloudflare.verdict.verifier));
  assert.equal(root.all('details').length >= 4, true);
});

test('run.js says a report of another format is unsupported', async () => {
  const report = { ...published('latest-run.json'), format: 2 };
  const { status } = await render({ 'latest-run.json': report, 'history.json': { runs: [] } });
  assert.equal(status, 'Unsupported run report');
});

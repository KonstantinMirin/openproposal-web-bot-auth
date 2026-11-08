/**
 * cfbot: an agent built only on Cloudflare's web-bot-auth library (pinned 0.2.0)
 * and its http-message-sig (0.3.0). It is a second, independent implementation.
 *
 * - It signs requests to the seller as its own origin. The seller has no record
 *   of it, so its identity is established and it has no principal there.
 * - It serves its own signed key directory.
 * - POST /verify checks the caller's signature with Cloudflare's verify(),
 *   after fetching and checking the caller's key directory.
 *
 * The /run/ routes are this agent's operator controls. No front routes them,
 * and each call carries X-Operator-Key, which must equal OPERATOR_KEY.
 */
import { createHash, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname } from 'node:path';
import { component, createSignature, verifySignature } from 'http-message-sig';
import { parseDictionary } from 'structured-headers';
import { HTTP_MESSAGE_SIGNATURES_DIRECTORY, generateNonce, sign, verify } from 'web-bot-auth';
import { signerFromJWK, verifierFromJWK } from 'web-bot-auth/crypto';

// SELF_ORIGIN is this agent's own origin; PEER_SELLER_ORIGIN is the seller it calls.
const ORIGIN = process.env.SELF_ORIGIN ?? 'https://cfbot.wba-demo.noetis.dev';
const SELLER = process.env.PEER_SELLER_ORIGIN ?? 'https://seller.wba-demo.noetis.dev';
const KEY_PATH = process.env.CFBOT_KEY ?? '/data/cfbot-key.jwk';
const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
const LIFETIME = 300;
const OPERATOR_KEY = process.env.OPERATOR_KEY ?? '';

// The key is minted on first boot. No other party is configured with it.
function loadOrCreateKey(path) {
  if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8'));
  const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(jwk), { mode: 0o600 });
  return jwk;
}
const key = loadOrCreateKey(KEY_PATH);
const signer = await signerFromJWK(key);
const { d, ...publicKey } = key;

// An agent without OPERATOR_KEY refuses every operator call.
function isOperator(req) {
  const sent = Buffer.from(String(req.headers['x-operator-key'] ?? ''));
  const expected = Buffer.from(OPERATOR_KEY);
  return expected.length > 0 && sent.length === expected.length && timingSafeEqual(sent, expected);
}

const digest = body => `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
const fieldsOf = headers => Object.entries(headers).map(([name, value]) => ({ name: name.toLowerCase(), value }));
const now = () => Math.floor(Date.now() / 1000);

// ── Signing, with the library's sign() ────────────────────────────────────

async function signedFetch(method, url, body = '') {
  const headers = { 'signature-agent': `sig1="${ORIGIN}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}"` };
  const additionalComponents = ['@method', '@target-uri'];
  if (body) {
    Object.assign(headers, { 'content-type': 'application/json', 'content-digest': digest(body) });
    additionalComponents.push('content-type', 'content-digest');
  }
  const t = now();
  const fields = await sign(
    { kind: 'request', method, targetUri: url, fields: fieldsOf(headers) },
    { signer, created: new Date(t * 1000), expires: new Date((t + LIFETIME) * 1000), nonce: generateNonce(), additionalComponents },
  );
  const response = await fetch(url, {
    method,
    body: body || undefined,
    headers: { ...headers, 'signature-input': fields.signatureInput, signature: fields.signature },
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

// ── The key directory (Web Bot Auth Appendix B.1) ─────────────────────────

async function directory(authority) {
  const body = JSON.stringify({ keys: [{ ...publicKey, kid: signer.keyid, use: 'sig' }] }, null, 2);
  const headers = { 'content-type': DIRECTORY_MEDIA_TYPE, 'content-digest': digest(body) };
  const t = now();
  const fields = await createSignature(
    { kind: 'response', status: 200, fields: fieldsOf(headers),
      request: { kind: 'request', method: 'GET', targetUri: `https://${authority}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`, fields: [] } },
    { label: 'key1', components: [component('@authority', { req: true }), 'content-digest'],
      parameters: { created: t, expires: t + 86400, keyid: signer.keyid, alg: signer.algorithm, tag: 'http-message-signatures-directory' },
      signer },
  );
  return { headers: { ...headers, 'signature-input': fields.signatureInput, signature: fields.signature }, body };
}

// ── Verifying, with the library's verify() ────────────────────────────────

/** The caller's directory, fetched without redirects; its status and its digest checked. */
async function fetchDirectory(url) {
  const response = await fetch(url, { redirect: 'error' });
  if (response.status !== 200) throw new Error(`directory status ${response.status}`);
  const body = await response.text();
  const headers = Object.fromEntries(response.headers);
  if (headers['content-digest'] !== digest(body)) throw new Error('directory Content-Digest does not match');
  return { headers, body };
}

/** A verifier for each key the directory lists; a key the library can't import is skipped. */
async function directoryVerifiers(body) {
  const keys = await Promise.all((JSON.parse(body).keys ?? []).map(k => verifierFromJWK(k).catch(() => undefined)));
  return keys.filter(Boolean);
}

/**
 * Verifies each of the directory's own signatures with http-message-sig (Web Bot
 * Auth Appendix B.1), and returns the ones verified, for the verdict.
 */
async function verifyDirectorySignatures(url, directory, keys) {
  const signed = { kind: 'response', status: 200, fields: fieldsOf(directory.headers),
                   request: { kind: 'request', method: 'GET', targetUri: url, fields: [] } };
  const input = parseDictionary(directory.headers['signature-input'] ?? '');
  if (input.size === 0) throw new Error(`${url} carries no directory signature`);
  const checked = [];
  for (const [label, [, params]] of input) {
    if (params.get('tag') !== 'http-message-signatures-directory') throw new Error(`directory signature ${label} has the wrong tag`);
    const verifier = keys.find(k => k.keyid === params.get('keyid'));
    if (verifier === undefined) throw new Error(`directory signature by unknown key ${params.get('keyid')}`);
    await verifySignature(signed, {
      label,
      policy: { algorithms: ['ed25519'], now: now(), requiredComponents: [component('@authority', { req: true }), 'content-digest'], requiredParameters: ['created', 'expires'] },
      resolveVerifier: async () => verifier,
    });
    checked.push({ label, keyid: verifier.keyid });
  }
  return checked;
}

/** The verifier for `keyid`: listed in the directory, and one of the keys that signed it. */
function pickKey(url, keys, checked, keyid) {
  const verifier = keys.find(k => k.keyid === keyid);
  if (verifier === undefined) throw new Error(`key ${keyid} is not in ${url}`);
  if (!checked.some(c => c.keyid === keyid)) throw new Error(`key ${keyid} did not sign ${url}`);
  return verifier;
}

/**
 * The verifier for the signature `candidate` names, from the caller's directory.
 * `checked` collects the directory signatures verified, for the verdict.
 */
async function resolveKey(candidate, checked) {
  if (candidate.signatureAgent === undefined) throw new Error('no covered Signature-Agent member');
  const url = `${new URL(candidate.signatureAgent.uri).origin}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`;
  const directory = await fetchDirectory(url);
  const keys = await directoryVerifiers(directory.body);
  checked.push(...await verifyDirectorySignatures(url, directory, keys));
  return pickKey(url, keys, checked, candidate.keyid);
}

async function verifyRequest(req, body) {
  const fields = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) fields.push({ name: req.rawHeaders[i].toLowerCase(), value: req.rawHeaders[i + 1] });
  const message = { kind: 'request', method: req.method, targetUri: `${ORIGIN}${req.url}`, fields };
  const checked = [];
  try {
    const verified = await verify(message, { resolver: candidate => resolveKey(candidate, checked) });
    const sent = fields.find(f => f.name === 'content-digest')?.value;
    return {
      ok: true,
      verifier: 'web-bot-auth@0.2.0 verify()',
      identity: new URL(verified.signatureAgent.uri).origin,
      keyid: verified.keyid,
      nonce: verified.nonce,
      directory_signatures: checked,
      // web-bot-auth 0.2.0 doesn't compare Content-Digest with the body; cfbot does.
      content_digest_matches: sent !== undefined && sent === digest(body),
    };
  } catch (e) {
    return { ok: false, error: String(e?.message ?? e) };
  }
}

// ── Routes ────────────────────────────────────────────────────────────────

const json = (res, status, value) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
};

/**
 * An error answer in the control plane's form (transport/control.py ErrorBody):
 * `error` is one of its codes ('operator-key', 'not-found', 'internal').
 */
const failed = (res, status, error, detail) => json(res, status, { error, detail });

function exampleCommit(lineItemId) {
  return JSON.stringify({
    entry: { role: 'commitment', version: 1, record_digest: `sha256:${'0'.repeat(64)}`, line_item_ids: [lineItemId],
             at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), idempotency_key: crypto.randomUUID() },
    writes: { [lineItemId]: { commitment: { basis: 'spend', amount: 50000, advertisers: [{ domain: 'cfbot-brand.example' }],
                                            flight: { start: '2029-11-02T00:00:00Z', end: '2029-12-21T23:59:59Z' } } } },
  });
}

// The routes any caller reaches.
const routes = {
  [`GET ${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`]: async (_req, res) => {
    const out = await directory(new URL(ORIGIN).host);
    res.writeHead(200, out.headers);
    res.end(out.body);
  },
  'GET /health': (_req, res) => json(res, 200, { ok: true }),
  'POST /verify': async (req, res, { body }) => {
    const verdict = await verifyRequest(req, body);
    json(res, verdict.ok ? 200 : 403, verdict);
  },
};

/** The proposal a control names in its JSON body (`{"proposal_id": ...}`). */
const proposalOf = body => JSON.parse(body || '{}').proposal_id ?? 'demo-wba-1';

// The operator's controls (transport/control.py CFBOT_*): each one has cfbot sign a
// request to the seller, and answers the seller's status and body.
const operatorRoutes = {
  'POST /run/whoami': async (_req, res) => json(res, 200, await signedFetch('GET', `${SELLER}/whoami`)),
  'POST /run/read': async (_req, res, { body }) =>
    json(res, 200, await signedFetch('GET', `${SELLER}/proposals/${proposalOf(body)}`)),
  'POST /run/commit': async (_req, res, { body }) =>
    json(res, 200, await signedFetch('POST', `${SELLER}/proposals/${proposalOf(body)}/commit`, exampleCommit('weather-app-ctv'))),
};

/** The route for a request: a public one, an operator one behind the key, or none. */
function route(req, pathname) {
  const name = `${req.method} ${pathname}`;
  if (routes[name]) return routes[name];
  if (!pathname.startsWith('/run/')) return undefined;
  if (!isOperator(req)) return (_req, res) => failed(res, 403, 'operator-key', 'operator key required');
  return operatorRoutes[name];
}

createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString('utf8');
  const { pathname } = new URL(req.url, ORIGIN);
  const handler = route(req, pathname) ?? ((_req, out) => failed(out, 404, 'not-found', `no route ${req.method} ${pathname}`));
  try {
    await handler(req, res, { body });
  } catch (e) {
    // The stack goes to the log, never into the body.
    console.error(e?.stack ?? e);
    if (!res.headersSent) failed(res, 500, 'internal', 'cfbot failed to answer; its log holds why');
  }
}).listen(8000, () => console.log(`cfbot ${signer.keyid} as ${ORIGIN}`));

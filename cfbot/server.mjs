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
 * The /run/ routes are this agent's operator controls; the TLS front doesn't
 * route them.
 */
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname } from 'node:path';
import { component, createSignature, verifySignature } from 'http-message-sig';
import { parseDictionary } from 'structured-headers';
import { HTTP_MESSAGE_SIGNATURES_DIRECTORY, generateNonce, sign, verify } from 'web-bot-auth';
import { signerFromJWK, verifierFromJWK } from 'web-bot-auth/crypto';

const ORIGIN = process.env.CFBOT_ORIGIN ?? 'https://cfbot.wba-demo.noetis.dev';
const SELLER = process.env.SELLER_ORIGIN ?? 'https://seller.wba-demo.noetis.dev';
const KEY_PATH = process.env.CFBOT_KEY ?? '/data/cfbot-key.jwk';
const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
const LIFETIME = 300;

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

/**
 * Fetches the caller's directory, verifies the directory's own signatures with
 * http-message-sig, and returns the verifier for `keyid`. The directory must be
 * signed, and signed by that key (Web Bot Auth Appendix B.1). `checked` collects
 * the directory signatures verified, for the verdict.
 */
async function resolveKey(candidate, checked) {
  if (candidate.signatureAgent === undefined) throw new Error('no covered Signature-Agent member');
  const origin = new URL(candidate.signatureAgent.uri).origin;
  const url = `${origin}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`;
  const response = await fetch(url, { redirect: 'error' });
  if (response.status !== 200) throw new Error(`directory status ${response.status}`);
  const body = await response.text();
  const headers = Object.fromEntries(response.headers);
  if (headers['content-digest'] !== digest(body)) throw new Error('directory Content-Digest does not match');
  const keys = (await Promise.all((JSON.parse(body).keys ?? []).map(k => verifierFromJWK(k).catch(() => undefined)))).filter(Boolean);
  const signed = { kind: 'response', status: 200, fields: fieldsOf(headers), request: { kind: 'request', method: 'GET', targetUri: url, fields: [] } };
  const input = parseDictionary(headers['signature-input'] ?? '');
  if (input.size === 0) throw new Error(`${url} carries no directory signature`);
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
  const verifier = keys.find(k => k.keyid === candidate.keyid);
  if (verifier === undefined) throw new Error(`key ${candidate.keyid} is not in ${url}`);
  if (!checked.some(c => c.keyid === candidate.keyid)) throw new Error(`key ${candidate.keyid} did not sign ${url}`);
  return verifier;
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

function exampleCommit(lineItemId) {
  return JSON.stringify({
    entry: { role: 'commitment', version: 1, record_digest: `sha256:${'0'.repeat(64)}`, line_item_ids: [lineItemId],
             at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), idempotency_key: crypto.randomUUID() },
    writes: { [lineItemId]: { commitment: { basis: 'spend', amount: 50000, advertisers: [{ domain: 'cfbot-brand.example' }],
                                            flight: { start: '2029-11-02T00:00:00Z', end: '2029-12-21T23:59:59Z' } } } },
  });
}

createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString('utf8');
  const { pathname, searchParams } = new URL(req.url, ORIGIN);
  try {
    if (req.method === 'GET' && pathname === HTTP_MESSAGE_SIGNATURES_DIRECTORY) {
      const out = await directory(new URL(ORIGIN).host);
      res.writeHead(200, out.headers);
      return res.end(out.body);
    }
    if (req.method === 'GET' && pathname === '/health') return json(res, 200, { ok: true });
    if (req.method === 'POST' && pathname === '/verify') {
      const verdict = await verifyRequest(req, body);
      return json(res, verdict.ok ? 200 : 403, verdict);
    }
    const proposal = searchParams.get('proposal_id') ?? 'demo-wba-1';
    if (req.method === 'POST' && pathname === '/run/whoami') return json(res, 200, await signedFetch('GET', `${SELLER}/whoami`));
    if (req.method === 'POST' && pathname === '/run/read') return json(res, 200, await signedFetch('GET', `${SELLER}/proposals/${proposal}`));
    if (req.method === 'POST' && pathname === '/run/commit') {
      return json(res, 200, await signedFetch('POST', `${SELLER}/proposals/${proposal}/commit`, exampleCommit('weather-app-ctv')));
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: String(e?.stack ?? e) });
  }
}).listen(8000, () => console.log(`cfbot ${signer.keyid} as ${ORIGIN}`));

# Web Bot Auth interop adapter protocol

An adapter connects one Web Bot Auth (WBA) implementation to a harness. Two
harnesses speak this protocol:

- `python -m iab_agentic_primitives.web_bot_auth.conformance run --adapter "<command>"`
  grades the implementation against this library. It splits the command with
  shell quoting rules and runs it without a shell.
- `tests/web_bot_auth/interop/run.mjs` in the repository grades it against one
  judge: Cloudflare's `web-bot-auth` and `http-message-sig` libraries at the
  versions pinned in its `package.json`, with the profile's rules from
  `policy.mjs`. It passes the command to a shell.

This file ships in the package, at
`iab_agentic_primitives/web_bot_auth/conformance/PROTOCOL.md`, beside the
vectors it grades.

An adapter is one executable. For each operation, the harness starts the
executable, writes one JSON object to its standard input, and reads one JSON
object from its standard output. With `--persistent`, the Node harness starts
the executable once and exchanges one JSON object per line in each direction.

```bash
npm ci --prefix tests/web_bot_auth/interop
node tests/web_bot_auth/interop/run.mjs --persistent \
  --adapter "python -m iab_agentic_primitives.web_bot_auth.conformance adapter --lines" \
  --json checks.json
```

## Shared shapes

- **Request**: `{ "method", "url", "headers", "body" }`. `headers` is an array
  of `[name, value]` pairs of strings, one per field line, in wire order, so a
  repeated field keeps each line; names are case-insensitive. `body` is the
  exact bytes on the wire: a string of UTF-8 text, or `{ "base64": "..." }`
  (standard Base64 with padding) when the bytes aren't UTF-8. It is `""` for a
  request with no body.
- **Response**: `{ "status", "headers", "body" }`.
- **Directory response**: `{ "url", "status", "headers", "body" }`, the signed
  response a key directory server sends for
  `<origin>/.well-known/http-message-signatures-directory`.
- **Key**: a private JWK, `{ "kty": "OKP", "crv": "Ed25519", "x", "d" }`. Every key
  is a published test key from `keys.json`, which a production verifier SHOULD
  refuse (WBA section 6.8). An adapter configures its implementation to accept
  them.
- **Time**: `now` is Unix seconds. The adapter uses it as the clock for signing
  and verification, never the system clock.
- **Refusal**: `{ "ok": false, "status", "rule", "error" }`. `status` is the HTTP
  status the implementation answers: `400`, `403`, `429`, or `503`. `rule` is a
  rule of the shared vocabulary in `vectors/refusals.json`, which lists every
  rule with its status (it is generated from the `Refusal` enum). `error` is
  free text that the report shows.
- **Adapter failure**: a harness records an adapter that crashes, times out,
  or answers something that isn't a result as a refusal with no `status` and
  the rule `adapter-crash` (with the exit code), `adapter-timeout`,
  `adapter-invalid`, or `adapter-error`. No expected refusal accepts it.

## Operations

### `sign_request`

Sign `request` as the identity `origin`, at `now`, under the profile.

```json
{ "op": "sign_request", "key": { "kty": "OKP", "crv": "Ed25519", "x": "...", "d": "..." },
  "origin": "https://buyer.example.com", "request": { "method": "POST", "url": "...", "headers": [["Content-Type", "application/json"]], "body": "..." },
  "now": 1794052800 }
```

The output is the signed request: the input request with `Signature-Agent`
(the key directory URL, `<origin>/.well-known/http-message-signatures-directory`),
`Signature-Input`, `Signature`, and, when the request has a body,
`Content-Digest` added.

### `sign_directory`

Serve and sign the key directory of `origin`, which publishes `keys`, at `now`.

```json
{ "op": "sign_directory", "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "...", "d": "..." }],
  "origin": "https://buyer.example.com", "now": 1794052800 }
```

The output is the directory response.

### `sign_response`

Sign `response` as the identity `origin`, at `now`, as the answer to `request`
(which carries its own signature when the request was signed).

```json
{ "op": "sign_response", "key": { "...": "..." }, "origin": "https://seller.example.com",
  "request": { "...": "..." }, "response": { "status": 200, "headers": [["Content-Type", "application/json"]], "body": "..." }, "now": 1794052800 }
```

The output is the signed response.

### `verify_request`

Verify `request` at `now`, as the verifier whose own authority is `authority`
(its configured host and port, such as `seller.example.com`; § 2.8.4 step 5
refuses a request signed for another, with the rule `authority`).
`directories` maps each origin to the signed directory response its well-known
path serves; an origin absent from the map serves no directory, and the
adapter fetches nothing from the network. `prior` lists requests to verify
first, with the same replay state, which is how the harness builds a replay
without reaching into the implementation's replay store.

```json
{ "op": "verify_request", "request": { "...": "..." }, "authority": "seller.example.com",
  "directories": { "https://buyer.example.com": { "url": "...", "status": 200, "headers": [["Content-Type", "application/json"]], "body": "..." } },
  "now": 1794052810, "prior": [] }
```

The output is `{ "ok": true, "identity", "keyid" }`, where `identity` is the
origin the implementation attributes the request to, whichever `Signature-Agent`
form named it, or a refusal.

### `verify_directory`

Verify the signed directory response of `origin` at `now`.

```json
{ "op": "verify_directory", "origin": "https://buyer.example.com", "response": { "...": "..." }, "now": 1794052810 }
```

The output is `{ "ok": true, "keyids" }` or a refusal. A directory refusal is a
`403` with a `directory-*` rule, the refusal the request that needed the key
gets.

### `verify_response`

Verify `response` to `request` at `now`, with `directories` as for
`verify_request`. When `expected_origin` is given, the response must be signed
by that origin (rule `origin-mismatch`).

```json
{ "op": "verify_response", "request": { "...": "..." }, "response": { "...": "..." },
  "directories": { "https://seller.example.com": { "...": "..." } }, "now": 1794052810,
  "expected_origin": "https://seller.example.com" }
```

The output is `{ "ok": true, "identity", "keyid", "bound" }` or a refusal.

## What the harness runs

`run.mjs` runs three suites and records, for each message, the adapter's
verdict, the judge's verdict, and the bare library's verdict:

- **`vectors`**: the committed vectors, each sent as its own `operation`,
  unchanged, at its `reference_now`; the operation names the verification
  that grades it and carries the signed directories it needs.
- **`live`**: the adapter signs a `POST`, a `GET`, a response, and its own
  directory, and the judge verifies them; then the judge signs and the adapter
  verifies, once with the key directory URL and once with the bare origin in
  `Signature-Agent`. Tampered copies (URL, body, status, or another request) must fail in
  both. The judge signs requests with the library's own `sign()` and
  `generateNonce`, which produces padded standard base64.
- **`scenarios`**: the judge signs every scenario in `scenarios.json` at the
  run's clock, and the adapter verifies it.

A check passes when the adapter and the judge both give the expected outcome
(a pass with the expected identity, or a refusal with the expected status and
rule) and the bare library agrees with the tier: tier `wba` means the bare library
already gives the expected outcome, and tier `profile` means it gives the
opposite one, so only the profile's rules decide it. `run.mjs --self` uses the
judge as the adapter, which checks every tier against the bare library.

web-bot-auth 0.2.0 has no response verifier, so the judge verifies response
signatures with `http-message-sig`, which resolves the `req` and `key`
component parameters.

## Out of scope

The harness serves directories from data. It doesn't grade live fetches, the
fetch rules (HTTPS, resolved-address checks, redirects, size and time limits),
or directory caching; the Python tests in `tests/web_bot_auth/` grade those.

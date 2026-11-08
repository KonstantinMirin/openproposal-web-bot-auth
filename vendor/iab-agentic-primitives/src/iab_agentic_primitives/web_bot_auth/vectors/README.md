# Web Bot Auth profile conformance vectors

These vectors grade an implementation of the Web Bot Auth (WBA) profile that
OpenProposal 3.0 § 2.8 defines and `WEB_BOT_AUTH.md` describes. A signer written
with one WBA or RFC 9421 library and a verifier written with another use them to
agree on the wire format and on what a verifier refuses. The profile follows
[draft-ietf-webbotauth-httpsig-protocol-01](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/01/),
and "WBA section" numbers in the vectors refer to that draft unless a basis
names -00 or an RFC. Cloudflare's `web-bot-auth` 0.2.0, which the interop
harness runs, implements -00; the sections the vectors cite have the same
numbers in both drafts.

## Test keys are public

`keys.json` publishes the private seed of every test key in
`_private_d_for_test_only`, so you can reproduce every signature. Each seed is
SHA-256 of the ASCII string `aamp-wba-test/<seed_name>`, used as the Ed25519
private key. Each `kid` is the key's JWK thumbprint (RFC 7638; RFC 8037
Appendix A.3 for Ed25519), and each entry's `identity` is the origin whose key
directory publishes the key.

**These keys are valid only for grading against this suite.** WBA section 6.8
says test keys "MUST NOT be used in production", and verifiers SHOULD reject
them when detected. This library's `RequestVerifier` and `ResponseVerifier`
always refuse them (`rules.TEST_KEY_IDS`), unless a conformance run makes them
with `keys=CONFORMANCE_KEYS`.

The origins `https://buyer.example.com`, `https://seller.example.com`, and
`https://other.example.com` are placeholders. A harness serves each directory from
the vector's `directories` object instead of fetching it.

## Scope

Signers name their key directory URL,
`https://<host>/.well-known/http-message-signatures-directory`, in
`Signature-Agent`; `positive/004` shows the bare-origin form a draft -00 signer
sends, which names the same origin. The vectors exercise the profile's rules:
the `Signature-Agent` value, the covered `Signature-Agent` member,
key selection by thumbprint from the directory the member names, the required
nonce, replay refusal, one signature per request, the signed directory response,
the signed response and its binding to the request, the verifier's own
authority, the target URI, and the `400`, `403`, and `429` responses, each with its rule. They don't exercise live directory fetches, the fetch rules, or
caching; the unit tests in `tests/web_bot_auth/` grade those.

## File layout

```
vectors/
├── README.md                                   this file
├── keys.json                                   three Ed25519 test keys, one per identity, with private seeds
├── scenarios.json                              scenarios as data, signed by a harness at run time
├── refusals.json                               the refusal vocabulary: every rule and its status
├── positive/                                   messages that MUST verify
│   ├── 001-single-signer-request.json          the buyer commits to proposal prop_7
│   ├── 002-signed-directory-response.json      the buyer's directory, signed per key (WBA Appendix B.1)
│   ├── 003-signed-response.json                the seller's CommitResult, bound to positive/001
│   ├── 004-origin-form-request.json            the same commit, Signature-Agent in the draft -00 origin form
│   └── 005- to 012-target-uri-*.json           a GET to each URL whose @target-uri the profile normalizes or
│                                               keeps as sent: ids[]=1, a|b, {json}, a^b, %20, :443, mixed case,
│                                               and dot segments
└── negative/                                   messages a verifier MUST refuse, with the status and rule
    ├── 001-missing-nonce.json                  → 403 nonce-missing
    ├── 002-replayed-nonce.json                 → 429 nonce-replayed (after verifying positive/001)
    ├── 003-signature-agent-not-covered.json    → 403 signature-agent-not-covered
    ├── 004-key-not-in-named-directory.json     → 403 key-not-found (another origin publishes the key)
    ├── 005-malformed-signature-agent.json      → 400 parse
    ├── 006-two-signatures.json                 → 403 multiple-signatures (each valid on its own)
    ├── 007-response-not-bound.json             → 403 response-not-bound
    └── 008-key-not-in-named-directory-warm-cache.json
                                                → 403 key-not-found (negative/004, warm cache)
```

## Vector format

`iab_agentic_primitives.web_bot_auth.conformance.models` types every file, and
the files validate strictly when they are read: a member nobody declared, a
string where a boolean belongs, or a float where an integer belongs is refused.

- **`name`**: a one-line description.
- **`tier`**: `wba` when the reference libraries with no profile rules already
  give the expected outcome; `profile` when only the profile's rules do.
- **`spec`** and **`spec_reference`**: the specification, and the URL of the
  rule's heading in `WEB_BOT_AUTH.md`.
- **`signing_profile`**: always `web-bot-auth`.
- **`reference_now`**: Unix seconds, the verifier's clock.
- **`operation`**: the one operation that grades the vector, ready to send to
  an adapter as it is (`conformance/PROTOCOL.md`): `verify_request`,
  `verify_response`, or `verify_directory`. It carries the message, the
  verifier's clock (`now`, the same as `reference_now`), the authority or
  origin the verifier holds the message to, and each directory the message's
  keys come from, signed at `reference_now`; an origin absent from
  `directories` serves none. A `verify_request` may list `prior` requests: a
  black-box runner verifies each of them first, with the same directories and
  clock. Reset verifier state before every vector.

  A message's `headers` is an array of `[name, value]` pairs, one per field
  line, in wire order; names are case-insensitive. Its `body` is the exact
  bytes on the wire: a string of UTF-8 text, or `{"base64": ...}` when the
  bytes aren't UTF-8. Binary header values use RFC 8941 `sf-binary` (standard
  Base64 with padding).
- **`replay_cache_entries`**: the replay state the `prior` requests leave, as
  `{ identity, nonce, ttl_seconds }`, for a white-box harness.
- **`expected_signature_base`**: keyed by label, the signature base per RFC 9421
  section 2.5, lines joined with `\n` and no trailing newline. Diff your
  computed base against it before you look at signatures.
- **`expected`**: `ok`, a JSON boolean; for a pass, the `identity` the message
  is attributed to (none for a directory); for a refusal, `status` and `rule`,
  a rule of `refusals.json` and its status, a JSON integer, and, for a `403` or `429`,
  `accept_signature`, the `Accept-Signature` member a verifier SHOULD send
  (conformance grades the status and the rule, not this field). `rationale`
  says why.
- **`$comment`**: free-form notes, including which non-conformant verifier
  behavior the vector catches.

### Scenarios

`scenarios.json` holds scenarios as data instead of signed messages. A harness
signs each one at run time, so no committed signature expires.

- **`verifier`**: the verifier's own authority, which a request scenario's
  `authority` replaces.
- **`signer`** and **`responder`**: the identity, `kid`, and default
  `Signature-Agent` value (the key directory URL) that sign request scenarios
  and response scenarios.
- **`requests`**, **`components`**, **`parameters`**: the base requests (`post`
  and `get`), their default components, and the default signature parameters.
  `{label}` stands for the signature's label. `created` and `expires` are
  offsets in seconds from the harness clock. A `nonce` object asks for that many
  random bytes in that encoding: `base64url` (unpadded), `base64` (padded), or
  `base64url-padded`.
- **`request_scenarios`**: each overrides `base` (`post` by default), `label`,
  `components`, `parameters` (`null` omits one), `signature_agent`, or
  `authority`. `extra_signature` adds a second
  signature. `after_signing` changes `headers`, appends `append_to_body`, or
  appends raw `append_members` to `Signature-Input` and `Signature`.
  `directories` lists the `kid` values each origin serves.
- **`directory_parameters`** and **`directory_max_age`**: what every directory
  signature carries unless a scenario moves it (`created` and `expires`
  offsets), and the directory's `Cache-Control` `max-age`.
- **`directory_scenarios`**: each overrides how the signer's directory is
  signed: `keys`, `unsigned_keys`, `authority`, `parameters`, `components`,
  `content_type`, and `after_signing` (`append_to_body`). A refused directory is a `403` with a
  `directory-*` rule, the refusal the request that needed its key gets.
- **`response`**, **`response_components`**, **`response_parameters`**,
  **`response_scenarios`**: the base response (a `CommitResult`), its components
  with (`bound`) and without (`unbound`) the request binding, and scenarios that
  override `components`, `parameters`, `request` (`bound`, the default, signs
  the request; `unbound` sends it unsigned), or `after_signing` (`status`,
  `append_to_body`, `request_headers`).
- **`target_uris`**: each is a `GET` to `url`, as a caller writes it, and
  `wire`, its `@target-uri`: the URL as it travels on the wire
  (`WEB_BOT_AUTH.md`, "The target URI"). Each side signs the `GET` and the
  other verifies it as the signer's identity.
- **`expected`**, **`tier`**, **`basis`**: `expected` as for vectors, `tier`
  as for vectors (`wba` by default), and `basis`, the rule's source.

## Conformance

An implementation conforms when every positive vector verifies with the
expected identity, every negative vector gets its status and rule, and every
scenario gets its expected outcome. Ed25519 is deterministic, so signing a committed
`expected_signature_base` with the published seed reproduces the committed
`Signature` byte for byte.

Several negative vectors carry valid signatures on purpose: `001`, `003`, `006`,
and `007` verify once the targeted check is removed, and `004` verifies under a
verifier that looks keys up by thumbprint alone. A verifier that accepts one of
them has skipped a profile rule.

## Running and regenerating

- `python -m iab_agentic_primitives.web_bot_auth.conformance run [--adapter "<command>"]`
  grades an implementation through the adapter protocol of
  `conformance/PROTOCOL.md`, which ships beside these files.
- `python -m iab_agentic_primitives.web_bot_auth.conformance --regenerate`
  writes every file here except this README, from the generator, and deletes
  a vector the generator no longer produces; nothing else is touched.
  `--check` names each file that differs, is missing, or isn't generated, and
  exits 1 when there is one. Don't edit the vector files by hand.
- `tests/web_bot_auth/interop/run.mjs` grades the same files against
  Cloudflare's `web-bot-auth` library.

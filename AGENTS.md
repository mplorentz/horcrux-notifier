# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this project is

`horcrux-notifier` is a small Rust HTTP service that relays push notifications
for the Horcrux mobile app (recovery/steward coordination over Nostr). It does
**not** subscribe to relays, does **not** see plaintext vault data, and does
**not** act on behalf of any user. Its job is narrow:

1. Let a Horcrux user register their FCM device token under their Nostr pubkey.
2. Let that user maintain a consent allowlist of pubkeys that may push them.
3. Accept sender-triggered `POST /push` requests, authenticate the sender via
   NIP-98, check the recipient's consent list, rate-limit, and forward the
   resulting message to FCM.

The client app lives in a separate repo ([`horcrux_app`]). Changes here must
stay compatible with the `HorcruxNotificationService` client there. See the
"Client contract" section below.

## Quick reference

```bash
# Build everything (binary + tests, debug)
cargo build

# Unit tests + integration tests (uses an in-memory FCM mock, no network)
cargo test

# Format and lint (run both before committing)
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Run locally (needs .env with HORCRUX_NOTIFIER_FCM_SERVICE_ACCOUNT set)
cp .env.example .env
# edit .env
cargo run
```

### Before every commit

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test`
- [ ] If you changed `migrations/*.sql`, the filenames are numbered and
      additive — never rewrite a past migration.
- [ ] If you changed the HTTP surface, update `README.md` and the
      "Client contract" section below; double-check the client in
      `horcrux_app` for required changes.

### Never commit

- Any real FCM service-account JSON (anything matching
  `fcm-service-account*.json` — see `.gitignore`).
- Real pubkeys or device tokens in tests or fixtures. Use the key generator in
  `tests/common/mod.rs::new_keypair`.

## Repository layout

```
src/
  main.rs         # binary entrypoint; tracing, config, graceful shutdown
  lib.rs          # re-exports + router/state wiring; `spawn_prune_task`
  config.rs       # env-driven Config
  state.rs        # AppState (Config, Pool, dyn FcmSender)
  error.rs        # ApiError + IntoResponse mapping to JSON
  db.rs           # all SQLx queries; connect() runs embedded migrations
  auth.rs         # NIP-98 middleware, AuthedJson / AuthedEmpty extractors
  ratelimit.rs    # SQLite-backed sliding-window limits + prune task
  fcm.rs          # FCM v1 client + service-account OAuth2 JWT; Platform enum
  routes/
    mod.rs        # Router composition; NIP-98 is applied as a route_layer
    health.rs     # GET /health (unauthed)
    register.rs   # POST/DELETE /register (recipient)
    consent.rs    # PUT /consent, DELETE /consent/{sender_pubkey} (recipient)
    push.rs       # POST /push (sender)
migrations/
  0001_init.sql   # additive-only; new migrations get a new numeric prefix
tests/
  common/mod.rs   # TestApp, spawn_app, new_keypair, sign_nip98_header
  integration.rs  # end-to-end HTTP tests using the MockSender
```

## Architectural invariants

These are the properties an agent must preserve. Violating any of them is a
security regression.

1. **Every non-`/health` route runs through `nip98_middleware`.** Never add a
   new authenticated route outside of the `route_layer(... nip98_middleware)`
   group in `routes/mod.rs`.
2. **The authenticated principal is only the NIP-98 pubkey.** Never trust any
   pubkey passed in the request body or path to identify the caller. Handlers
   must read the pubkey from `Nip98Context` / `AuthedJson`.
3. **Request URL and body integrity are already verified by the middleware.**
   Do not re-parse the body from the raw request — use `AuthedJson<T>`, which
   reads the pre-buffered body out of the middleware-inserted extension.
4. **`/push` must pass three gates in this order, before any FCM call:**
   (a) recipient has a device registered, (b) `is_consented(recipient, sender)`,
   (c) `ratelimit::check_push`. Record the attempt *before* dispatching so a
   flapping FCM does not defeat rate limits.
5. **Pubkeys are always 64-char lowercase hex on the wire and in the DB.** Use
   `trim().to_ascii_lowercase()` plus the local `is_hex_pubkey` helper before
   touching SQLite.
6. **Migrations are additive.** Never edit an existing file in `migrations/`;
   add a new `000N_*.sql`. SQLite is shared with running production databases.
7. **The FCM `data` map must contain only string values.** `FcmClient::build_payload`
   enforces this; do not bypass it.

## Testing patterns

- Integration tests spin up the real Axum router against a per-test SQLite
  file in a `tempfile::TempDir` and inject a `MockSender` (see
  `fcm::test_util::MockSender`, gated behind the `test-util` feature, which the
  dev-dep self-reference enables automatically).
- Prefer adding tests to `tests/integration.rs` over new `#[cfg(test)] mod tests`
  blocks in library code, unless you're testing a pure helper (e.g. the NIP-98
  signature verifier, the FCM payload shape).
- `tests/common/mod.rs::send_json` signs NIP-98 automatically when you pass a
  `SecretKey`. Use `new_keypair()` to generate fresh identities per test.
- There is no live FCM test. If you need to exercise the real HTTP client,
  add a `wiremock` server in the test.

## NIP-98 gotchas

The NIP-98 middleware is the only line of defense. A few things that have
bitten people before:

- The `u` tag must match the **full request URL**, reconstructed from
  `X-Forwarded-Proto` + (`X-Forwarded-Host` or `Host`) + `path_and_query`.
  This means tests must set those headers, and production must front the
  service with a reverse proxy that sets them.
- The `method` tag is compared case-insensitively.
- The `payload` tag is required on POST/PUT/PATCH **when the body is non-empty**
  and is the hex SHA-256 of the *raw* body. An empty POST body skips the check.
- The event id is recomputed on the server from `[0, pubkey, created_at, kind,
  tags, content]` with `serde_json::to_string` (no pretty-printing). Never
  trust the client-supplied `id`.
- Schnorr verification is delegated to `secp256k1::Secp256k1::verification_only()`
  with `XOnlyPublicKey::from_slice`; do not accept compressed (33-byte) pubkeys.

## Client contract (horcrux_app)

Keep the wire format stable with the Flutter client. The authoritative client
code lives in `horcrux_app/lib/services/horcrux_notification_service.dart` (to
be created in Phase 4). The contract:

- `Authorization: Nostr <base64(event_json)>` on every authenticated call.
- Hex pubkeys are lowercase, 64 chars, no prefix.
- `POST /push` body matches `routes::push::PushRequest`. The client decides
  whether to embed `event_json` (≤ 3 KB) or send `event_id` + `relay_hints`.
- `POST /register` / `PUT /consent` bodies match
  `routes::register::RegisterRequest` / `routes::consent::ReplaceConsentRequest`.

Breaking changes to any of these require a coordinated client release. Prefer
additive optional fields (`#[serde(default)]`) and gate behavior behind the
presence of new fields.

## Operational notes

- State is local SQLite (WAL mode, `synchronous=NORMAL`). To back it up,
  snapshot the whole directory that `HORCRUX_NOTIFIER_DATABASE_URL` points to.
- The `spawn_prune_task` background job deletes rate-limit rows older than the
  longest configured window every 5 minutes. It's best-effort; a missed tick
  just grows the table a little.
- Logs are structured via `tracing`; `RUST_LOG` follows env-filter syntax.
- The reverse proxy is responsible for TLS and per-IP rate limiting. The Rust
  service only trusts its per-principal and per-pair limits.

## What this server intentionally does NOT do

Keep the scope small. If an agent is tempted to add any of these, stop and
raise it as a design question first:

- Subscribe to Nostr relays (not our job; the client knows what events exist).
- Decrypt NIP-44 payloads (the notifier never sees plaintext events).
- Store notification history, read receipts, delivery status, or any user data
  beyond `(pubkey, device_token, platform)` and a consent list.
- Send pushes on its own schedule (all pushes are sender-triggered via
  `POST /push`).
- Support multiple devices per pubkey (single-device-per-pubkey keeps the model
  simple; we'll revisit if users ask).

## Related docs

- `README.md` — user-facing: endpoints, configuration, deployment.
- `../horcrux_app` — the mobile client. See its `CLAUDE.md` and
  `DESIGN_GUIDE.md` for the overall Horcrux product shape.
- [NIP-98] — HTTP Auth specification.
- [FCM v1 HTTP API](https://firebase.google.com/docs/cloud-messaging/send-message)

[`horcrux_app`]: https://github.com/planetary-social/horcrux_app
[NIP-98]: https://github.com/nostr-protocol/nips/blob/master/98.md

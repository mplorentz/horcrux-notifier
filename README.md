# horcrux-notifier

Push-notification relay for [Horcrux](https://github.com/planetary-social/horcrux_app).
It accepts signed push requests from Horcrux clients, checks that the recipient
has authorized the sender, and forwards the message to Firebase Cloud Messaging
(FCM). Every request is authenticated with a [NIP-98] HTTP Auth event, so the
server never trusts the client-claimed identity.

This server is intentionally simple: a single SQLite database, one HTTP port,
no relay integration, no persistent message queue. It is deliberately **not**
end-to-end encrypted on the title/body plane — the sending client composes the
human-readable notification text, and the notifier passes that text verbatim to
FCM. The sensitive Nostr event itself is embedded in the `data` payload as an
opaque NIP-44 gift wrap; only the recipient's device can decrypt it.

> **Status:** alpha. This lives inside the `horcrux_app` repo for convenience
> and will be split into its own repository once the protocol stabilizes.

## Endpoints

All endpoints except `/health` require `Authorization: Nostr <base64_event>`
where the event is a kind-27235 NIP-98 event signed by the acting principal.

| Method | Path                        | Principal | Purpose                                                                |
| ------ | --------------------------- | --------- | ---------------------------------------------------------------------- |
| GET    | `/health`                   | —         | Liveness probe.                                                        |
| POST   | `/register`                 | recipient | Upsert FCM device token for the signer's pubkey.                       |
| DELETE | `/register`                 | recipient | Remove the signer's device.                                            |
| PUT    | `/consent`                  | recipient | Replace the signer's consent allowlist atomically.                     |
| DELETE | `/consent/{sender_pubkey}`  | recipient | Remove one entry from the signer's consent list.                       |
| POST   | `/push`                     | sender    | Trigger a push to a recipient who has authorized the sender.           |

### Request bodies

```jsonc
// POST /register
{ "device_token": "fcm-token", "platform": "android" }    // or "ios"

// PUT /consent
{ "authorized_senders": ["<64-char hex pubkey>", ...] }   // full replacement

// POST /push
{
  "recipient_pubkey": "<hex>",
  "title": "Alice is requesting recovery",
  "body":  "Tap to respond for Family Vault.",
  "event_id":   "<hex>",          // optional if event_json present
  "event_json": { ... },          // optional, <= 3 KB
  "relay_hints": ["wss://..."]    // optional
}
```

The `/push` handler rejects payloads where neither `event_json` nor `event_id`
is set. Clients choose: embed the full event (≤ 3 KB) so the app can process
offline, or send just the id + hints and let the app fetch on tap.

## Authentication (NIP-98)

Every authenticated request carries a fresh Nostr event:

- `kind == 27235`
- `created_at` within `HORCRUX_NOTIFIER_NIP98_MAX_AGE_SECS` of server time
- `tags` must contain `["u", <request_url>]` and `["method", <HTTP_METHOD>]`
- for POST/PUT/PATCH with a non-empty body: `["payload", hex(sha256(body))]`
- `id` equals the canonical NIP-01 event hash
- `sig` is a valid Schnorr signature over `id` for the event's `pubkey`

The request URL used for the `u` tag check is reconstructed from the
`X-Forwarded-Proto`, `X-Forwarded-Host`, and `Host` headers behind a reverse
proxy. Configure your reverse proxy (see `Caddyfile`) accordingly.

## Rate limiting

Enforced in-process against SQLite, surviving restarts:

| Scope                          | Default        |
| ------------------------------ | -------------- |
| `/push` per sender/recipient   | 1 per 30s      |
| `/push` per recipient          | 60 per hour    |
| `/register` per pubkey         | 10 per hour    |

Put a reverse proxy (Caddy) in front for per-IP global limits.

## Configuration

All via environment variables (see `.env.example` for the full list):

| Var                                       | Required | Default                                                         |
| ----------------------------------------- | -------- | --------------------------------------------------------------- |
| `HORCRUX_NOTIFIER_BIND`                   | no       | `0.0.0.0:8080`                                                  |
| `HORCRUX_NOTIFIER_DATABASE_URL`           | no       | `sqlite://data/horcrux_notifier.db?mode=rwc`                    |
| `HORCRUX_NOTIFIER_FCM_SERVICE_ACCOUNT`    | **yes**  | —                                                               |
| `HORCRUX_NOTIFIER_NIP98_MAX_AGE_SECS`     | no       | `60`                                                            |
| `HORCRUX_NOTIFIER_PUSH_PAIR_WINDOW_SECS`  | no       | `30`                                                            |
| `HORCRUX_NOTIFIER_PUSH_PAIR_MAX`          | no       | `1`                                                             |
| `HORCRUX_NOTIFIER_PUSH_RECIPIENT_WINDOW_SECS` | no   | `3600`                                                          |
| `HORCRUX_NOTIFIER_PUSH_RECIPIENT_MAX`     | no       | `60`                                                            |
| `HORCRUX_NOTIFIER_REGISTER_WINDOW_SECS`   | no       | `3600`                                                          |
| `HORCRUX_NOTIFIER_REGISTER_MAX`           | no       | `10`                                                            |
| `RUST_LOG`                                | no       | `horcrux_notifier=info,tower_http=info`                         |

The FCM service account file must be a Google service-account JSON with
`roles/firebaseadmin` or at least the "Firebase Cloud Messaging API Admin"
role.

## Running locally

```bash
cargo run
```

With a .env file:

```bash
cp .env.example .env
# Edit .env (set HORCRUX_NOTIFIER_FCM_SERVICE_ACCOUNT to a valid path).
cargo run
```

## Testing

```bash
cargo test
```

Integration tests use an in-memory FCM mock; no network or service account is
required.

## Deployment

```bash
docker build -t horcrux-notifier .
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/data:/var/lib/horcrux-notifier/data \
  -v $(pwd)/fcm-service-account.json:/etc/horcrux_notifier/fcm-service-account.json:ro \
  -e HORCRUX_NOTIFIER_FCM_SERVICE_ACCOUNT=/etc/horcrux_notifier/fcm-service-account.json \
  -e HORCRUX_NOTIFIER_DATABASE_URL=sqlite:///var/lib/horcrux-notifier/data/horcrux_notifier.db?mode=rwc \
  horcrux-notifier
```

Terminate TLS with Caddy (see `Caddyfile`) or any reverse proxy that sets
`X-Forwarded-Host` and `X-Forwarded-Proto`.

## Data model

See `migrations/0001_init.sql`. Three tables:

- `devices(pubkey, device_token, platform, ...)` — one device per pubkey
- `consents(recipient_pubkey, sender_pubkey, ...)` — recipient's allowlist
- `push_attempts(...)` — rolling window for rate limiting (pruned every 5 min)

## What the server learns

- Your pubkey ↔ FCM device token mapping
- Your consent list (the pubkeys you accept pushes from)
- Per push: `{sender_pubkey, recipient_pubkey, title, body, event_id}` — the
  title and body are plaintext; the Nostr event itself remains encrypted

If you'd rather not trust this notifier, run your own: it's one small Rust
binary and one SQLite file.

[NIP-98]: https://github.com/nostr-protocol/nips/blob/master/98.md

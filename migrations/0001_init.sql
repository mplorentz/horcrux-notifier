CREATE TABLE IF NOT EXISTS devices (
    pubkey        TEXT PRIMARY KEY,
    device_token  TEXT NOT NULL,
    platform      TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consents (
    recipient_pubkey TEXT NOT NULL,
    sender_pubkey    TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (recipient_pubkey, sender_pubkey)
);

CREATE INDEX IF NOT EXISTS idx_consents_recipient ON consents(recipient_pubkey);

CREATE TABLE IF NOT EXISTS push_attempts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_pubkey    TEXT NOT NULL,
    recipient_pubkey TEXT NOT NULL,
    attempted_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_attempts_sr   ON push_attempts(sender_pubkey, recipient_pubkey, attempted_at);
CREATE INDEX IF NOT EXISTS idx_push_attempts_r    ON push_attempts(recipient_pubkey, attempted_at);

-- Used to throttle /register abuse from a single pubkey.
CREATE TABLE IF NOT EXISTS register_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pubkey        TEXT NOT NULL,
    attempted_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_register_attempts_p ON register_attempts(pubkey, attempted_at);

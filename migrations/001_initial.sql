-- Devices: a device is identified by its public key. No user accounts.
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    push_token TEXT,
    platform TEXT CHECK (platform IN ('ios', 'android')),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_devices_public_key ON devices(public_key);

-- Cards: encrypted profile blobs. The server cannot read these.
CREATE TABLE cards (
    id TEXT PRIMARY KEY,
    owner_device_id TEXT NOT NULL REFERENCES devices(id),
    owner_secret_hash TEXT NOT NULL,
    encrypted_blob TEXT NOT NULL,
    blob_iv TEXT NOT NULL,
    blob_auth_tag TEXT NOT NULL,
    schema_version INT NOT NULL DEFAULT 1,
    version INT NOT NULL DEFAULT 1,
    child_alias TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_cards_owner ON cards(owner_device_id);

-- Card Subscriptions: a device granted access to a card via wrapped key.
CREATE TABLE card_subscriptions (
    id TEXT PRIMARY KEY,
    card_id TEXT NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id),
    wrapped_key TEXT NOT NULL,
    ephemeral_public_key TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'trusted' CHECK (role IN ('trusted', 'temporary', 'readonly')),
    expires_at TIMESTAMPTZ,
    last_fetched_at TIMESTAMPTZ,
    last_fetched_version INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(card_id, device_id)
);

CREATE INDEX idx_subs_device ON card_subscriptions(device_id);
CREATE INDEX idx_subs_card ON card_subscriptions(card_id);

-- Share Links: one-time-use or limited-use links for QR/deep link sharing.
CREATE TABLE share_links (
    id TEXT PRIMARY KEY,
    card_id TEXT NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'temporary' CHECK (role IN ('temporary', 'readonly')),
    max_uses INT NOT NULL DEFAULT 1,
    used_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_links_token ON share_links(token);

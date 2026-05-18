-- Add 'editor' role to subscriptions and share links.
-- Editors can update cards (they receive a wrapped copy of the owner secret).

ALTER TABLE card_subscriptions DROP CONSTRAINT IF EXISTS card_subscriptions_role_check;
ALTER TABLE card_subscriptions ADD CONSTRAINT card_subscriptions_role_check
    CHECK (role IN ('trusted', 'temporary', 'readonly', 'editor'));

ALTER TABLE share_links DROP CONSTRAINT IF EXISTS share_links_role_check;
ALTER TABLE share_links ADD CONSTRAINT share_links_role_check
    CHECK (role IN ('trusted', 'temporary', 'readonly', 'editor'));

-- Wrapped owner secret for editor subscriptions (ECDH-wrapped, same pattern as card key).
ALTER TABLE card_subscriptions ADD COLUMN IF NOT EXISTS wrapped_owner_secret TEXT;
ALTER TABLE card_subscriptions ADD COLUMN IF NOT EXISTS owner_secret_ephemeral_key TEXT;

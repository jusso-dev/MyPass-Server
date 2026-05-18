-- Allow 'trusted' role on share links (previously only 'temporary' and 'readonly').
-- All users should be able to receive a QR code or link regardless of role.

ALTER TABLE share_links DROP CONSTRAINT IF EXISTS share_links_role_check;
ALTER TABLE share_links ADD CONSTRAINT share_links_role_check
    CHECK (role IN ('trusted', 'temporary', 'readonly'));

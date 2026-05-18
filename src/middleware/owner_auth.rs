/// Owner authentication via HMAC-SHA256 secret verification.
///
/// The client stores a random 32-byte secret in its Keychain/Keystore for each
/// card it owns. To prove ownership, it sends the raw secret in the
/// `X-Owner-Secret` header. The server HMAC-SHA256 hashes it (using the server's
/// HMAC key from env) and constant-time compares with the stored hash on the card.
///
/// This avoids JWT, sessions, or any account system. Ownership proof is
/// a simple "something you have" — the secret that was generated at card creation.
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-SHA256 of a raw owner secret using the server's HMAC key.
///
/// The result is hex-encoded for storage in the database. This is a one-way
/// operation — the raw secret cannot be recovered from the hash.
pub fn hash_owner_secret(hmac_key: &str, raw_secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(raw_secret.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify a raw owner secret against a stored HMAC-SHA256 hash.
///
/// Uses constant-time comparison via the `hmac` crate's `verify_slice` method
/// to prevent timing attacks. Returns `true` if the secret matches.
pub fn verify_owner_secret(hmac_key: &str, raw_secret: &str, stored_hash: &str) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(raw_secret.as_bytes());

    // Decode the stored hex hash back to bytes for constant-time comparison
    match hex::decode(stored_hash) {
        Ok(expected) => mac.verify_slice(&expected).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let key = "test-hmac-key";
        let secret = "my-owner-secret-123";
        let hash = hash_owner_secret(key, secret);
        assert!(verify_owner_secret(key, secret, &hash));
        assert!(!verify_owner_secret(key, "wrong-secret", &hash));
    }
}

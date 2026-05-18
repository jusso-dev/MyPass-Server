/// Baseline security response headers applied to every response.
///
/// Each header is added via its own [`SetResponseHeaderLayer`] in [`build_router`].
/// Kept as constants here so the policy is in one place and easy to review.
///
/// HSTS is harmless on plain HTTP (the header is only honoured over HTTPS) so we
/// always emit it; the deploy is expected to terminate TLS at a reverse proxy.
pub const HSTS: &str = "max-age=31536000; includeSubDomains";
pub const CONTENT_TYPE_OPTIONS: &str = "nosniff";
pub const FRAME_OPTIONS: &str = "DENY";
pub const REFERRER_POLICY: &str = "no-referrer";
pub const PERMISSIONS_POLICY: &str =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()";
pub const COOP: &str = "same-origin";
pub const CORP: &str = "same-origin";

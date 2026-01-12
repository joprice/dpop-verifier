use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpopError {
    #[error("Multiple DPoP headers")]
    MultipleDpopHeaders,
    #[error("Invalid DPoP header")]
    InvalidDpopHeader,
    #[error("Missing DPoP header")]
    MissingDpopHeader,
    #[error("malformed DPoP JWT")]
    MalformedJws,
    #[error("Invalid algorithm")]
    InvalidAlg(String),
    #[error("unsupported DPoP alg")]
    UnsupportedAlg(String),
    #[error("invalid DPoP signature")]
    InvalidSignature,
    #[error("bad JWK: {0}")]
    BadJwk(&'static str),
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("Invalid method")]
    InvalidMethod,
    #[error("htm mismatch")]
    HtmMismatch,
    #[error("malformed htu, reason: {0}")]
    MalformedHtu(String),
    #[error("htu mismatch")]
    HtuMismatch,
    #[error("Malformed ath")]
    AthMalformed,
    #[error("missing ath")]
    MissingAth,
    #[error("ath mismatch")]
    AthMismatch,
    #[error("iat too far in future")]
    FutureSkew,
    #[error("DPoP proof too old")]
    Stale,
    #[error("DPoP replay detected")]
    Replay,
    #[error("storage error: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
    #[error("Jti too long")]
    JtiTooLong,
    #[error("Use Dpop nonce")]
    UseDpopNonce { nonce: String },
    #[error("Missing Nonce")]
    MissingNonce,
    #[error("Nonce mismatch")]
    NonceMismatch,
    #[error("Nonce is stale")]
    NonceStale,
    #[error("Invalid HMAC configuration")]
    InvalidHmacConfig,
}

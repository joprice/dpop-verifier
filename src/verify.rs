use crate::uri::{normalize_htu, normalize_method};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::jwk::{thumbprint_ec_p256, verifying_key_from_p256_xy};
use crate::nonce::IntoSecretBox;
use crate::replay::{ReplayContext, ReplayStore};
use crate::DpopError;
use p256::ecdsa::{signature::Verifier, VerifyingKey};

// Constants for signature and token validation
const ECDSA_P256_SIGNATURE_LENGTH: usize = 64;
#[cfg(feature = "eddsa")]
const ED25519_SIGNATURE_LENGTH: usize = 64;
const JTI_HASH_LENGTH: usize = 32;
const JTI_MAX_LENGTH: usize = 512;

#[derive(Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: Jwk,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Jwk {
    EcP256 {
        kty: String,
        crv: String,
        x: String,
        y: String,
    },
    #[cfg(feature = "eddsa")]
    OkpEd25519 { kty: String, crv: String, x: String },
}

/// Configuration for HMAC-based nonce mode.
///
/// Stateless HMAC-based nonces: encode ts+rand+ctx and MAC it.
#[derive(Clone, Debug)]
pub struct HmacConfig {
    pub secret: secrecy::SecretBox<[u8]>,
    pub max_age_seconds: i64,
    pub bind_htu_htm: bool,
    pub bind_jkt: bool,
    pub bind_client: bool,
}

impl HmacConfig {
    /// Create a new HMAC configuration with a secret that can be converted to `SecretBox<[u8]>`.
    ///
    /// Accepts either a `SecretBox<[u8]>` or any type that can be converted to bytes
    /// (e.g., `&[u8]`, `Vec<u8>`). Non-boxed types will be automatically converted to
    /// `SecretBox` internally.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dpop_verifier::{HmacConfig, NonceMode};
    ///
    /// // With a byte array (b"..." syntax)
    /// let config = HmacConfig::new(b"my-secret-key", 300, true, true, true);
    /// let mode = NonceMode::Hmac(config);
    ///
    /// // With a byte slice
    /// let secret_slice: &[u8] = b"my-secret-key";
    /// let config = HmacConfig::new(secret_slice, 300, true, true, true);
    ///
    /// // With a Vec<u8>
    /// let secret = b"my-secret-key".to_vec();
    /// let config = HmacConfig::new(&secret, 300, true, true, true);
    ///
    /// // With a SecretBox (already boxed)
    /// use secrecy::SecretBox;
    /// let secret_box = SecretBox::from(b"my-secret-key".to_vec());
    /// let config = HmacConfig::new(&secret_box, 300, true, true, true);
    /// ```
    pub fn new<S>(
        secret: S,
        max_age_seconds: i64,
        bind_htu_htm: bool,
        bind_jkt: bool,
        bind_client: bool,
    ) -> Self
    where
        S: IntoSecretBox,
    {
        HmacConfig {
            secret: secret.into_secret_box(),
            max_age_seconds,
            bind_htu_htm,
            bind_jkt,
            bind_client,
        }
    }
}

#[derive(Clone, Debug)]
pub enum NonceMode {
    Disabled,
    /// Require exact equality against `expected_nonce`
    RequireEqual {
        expected_nonce: String, // the nonce you previously issued
    },
    /// Stateless HMAC-based nonces: encode ts+rand+ctx and MAC it
    Hmac(HmacConfig),
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub max_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub nonce_mode: NonceMode,
    pub client_binding: Option<ClientBinding>,
}
impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Disabled,
            client_binding: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientBinding {
    pub client_id: String,
}

impl ClientBinding {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedDpop {
    pub jkt: String,
    pub jti: String,
    pub iat: i64,
}

/// Helper struct for type-safe JTI hash handling
struct JtiHash([u8; JTI_HASH_LENGTH]);

impl JtiHash {
    /// Create a JTI hash from the SHA-256 digest
    fn from_jti(jti: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(jti.as_bytes());
        let digest = hasher.finalize();
        let mut hash = [0u8; JTI_HASH_LENGTH];
        hash.copy_from_slice(&digest[..JTI_HASH_LENGTH]);
        JtiHash(hash)
    }

    /// Get the inner array
    fn as_array(&self) -> [u8; JTI_HASH_LENGTH] {
        self.0
    }
}

/// Parsed DPoP token structure
struct DpopToken {
    header: DpopHeader,
    payload_b64: String,
    signature_bytes: Vec<u8>,
    signing_input: String,
}

/// Structured DPoP claims
#[derive(Deserialize)]
struct DpopClaims {
    jti: String,
    iat: i64,
    htm: String,
    htu: String,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// Main DPoP verifier with builder pattern
pub struct DpopVerifier {
    options: VerifyOptions,
}

impl DpopVerifier {
    /// Create a new DPoP verifier with default options
    pub fn new() -> Self {
        Self {
            options: VerifyOptions::default(),
        }
    }

    /// Set the maximum age for DPoP proofs (in seconds)
    pub fn with_max_age_seconds(mut self, max_age_seconds: i64) -> Self {
        self.options.max_age_seconds = max_age_seconds;
        self
    }

    /// Set the future skew tolerance (in seconds)
    pub fn with_future_skew_seconds(mut self, future_skew_seconds: i64) -> Self {
        self.options.future_skew_seconds = future_skew_seconds;
        self
    }

    /// Set the nonce mode
    pub fn with_nonce_mode(mut self, nonce_mode: NonceMode) -> Self {
        self.options.nonce_mode = nonce_mode;
        self
    }

    /// Bind verification to a specific client identifier
    pub fn with_client_binding(mut self, client_id: impl Into<String>) -> Self {
        self.options.client_binding = Some(ClientBinding {
            client_id: client_id.into(),
        });
        self
    }

    /// Remove any configured client binding
    pub fn without_client_binding(mut self) -> Self {
        self.options.client_binding = None;
        self
    }

    /// Verify a DPoP proof
    pub async fn verify<S: ReplayStore + ?Sized>(
        &self,
        store: &mut S,
        dpop_compact_jws: &str,
        expected_htu: &str,
        expected_htm: &str,
        access_token: Option<&str>,
    ) -> Result<VerifiedDpop, DpopError> {
        // Parse the token
        let token = self.parse_token(dpop_compact_jws)?;

        // Validate header
        self.validate_header(&token.header)?;

        // Verify signature and compute JKT
        let jkt = self.verify_signature_and_compute_jkt(&token)?;

        // Parse claims
        let claims: DpopClaims = {
            let bytes = B64
                .decode(&token.payload_b64)
                .map_err(|_| DpopError::MalformedJws)?;
            serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?
        };

        // Validate JTI length
        if claims.jti.len() > JTI_MAX_LENGTH {
            return Err(DpopError::JtiTooLong);
        }

        // Validate HTTP binding (HTM/HTU)
        let (expected_htm_normalized, expected_htu_normalized) =
            self.validate_http_binding(&claims, expected_htm, expected_htu)?;

        // Validate access token binding if present
        if let Some(token) = access_token {
            self.validate_access_token_binding(&claims, token)?;
        }

        // Check timestamp freshness
        self.check_timestamp_freshness(claims.iat)?;

        let client_binding = self
            .options
            .client_binding
            .as_ref()
            .map(|binding| binding.client_id.as_str());

        // Validate nonce if required
        self.validate_nonce_if_required(
            &claims,
            &expected_htu_normalized,
            &expected_htm_normalized,
            &jkt,
            client_binding,
        )?;

        // Prevent replay
        let jti_hash = JtiHash::from_jti(&claims.jti);
        self.prevent_replay(store, jti_hash, &claims, &jkt, client_binding)
            .await?;

        Ok(VerifiedDpop {
            jkt,
            jti: claims.jti,
            iat: claims.iat,
        })
    }

    /// Parse compact JWS into token components
    fn parse_token(&self, dpop_compact_jws: &str) -> Result<DpopToken, DpopError> {
        let mut jws_parts = dpop_compact_jws.split('.');
        let (header_b64, payload_b64, signature_b64) =
            match (jws_parts.next(), jws_parts.next(), jws_parts.next()) {
                (Some(h), Some(p), Some(s)) if jws_parts.next().is_none() => (h, p, s),
                _ => return Err(DpopError::MalformedJws),
            };

        // Decode JOSE header
        let header: DpopHeader = {
            let bytes = B64
                .decode(header_b64)
                .map_err(|_| DpopError::MalformedJws)?;
            let val: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?;
            // MUST NOT include private JWK material
            if val.get("jwk").and_then(|j| j.get("d")).is_some() {
                return Err(DpopError::BadJwk("jwk must not include 'd'"));
            }
            serde_json::from_value(val).map_err(|_| DpopError::MalformedJws)?
        };

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature_bytes = B64
            .decode(signature_b64)
            .map_err(|_| DpopError::InvalidSignature)?;

        Ok(DpopToken {
            header,
            payload_b64: payload_b64.to_string(),
            signature_bytes,
            signing_input,
        })
    }

    /// Validate the DPoP header (typ and alg checks)
    fn validate_header(&self, header: &DpopHeader) -> Result<(), DpopError> {
        if header.typ != "dpop+jwt" {
            return Err(DpopError::MalformedJws);
        }
        Ok(())
    }

    /// Verify signature and compute JKT (JSON Key Thumbprint)
    fn verify_signature_and_compute_jkt(&self, token: &DpopToken) -> Result<String, DpopError> {
        let jkt = match (token.header.alg.as_str(), &token.header.jwk) {
            ("ES256", Jwk::EcP256 { kty, crv, x, y }) if kty == "EC" && crv == "P-256" => {
                if token.signature_bytes.len() != ECDSA_P256_SIGNATURE_LENGTH {
                    return Err(DpopError::InvalidSignature);
                }

                let verifying_key: VerifyingKey = verifying_key_from_p256_xy(x, y)?;
                let signature = p256::ecdsa::Signature::from_slice(&token.signature_bytes)
                    .map_err(|_| DpopError::InvalidSignature)?;
                verifying_key
                    .verify(token.signing_input.as_bytes(), &signature)
                    .map_err(|_| DpopError::InvalidSignature)?;
                // compute EC thumbprint
                thumbprint_ec_p256(x, y)?
            }

            #[cfg(feature = "eddsa")]
            ("EdDSA", Jwk::OkpEd25519 { kty, crv, x }) if kty == "OKP" && crv == "Ed25519" => {
                use ed25519_dalek::{Signature as EdSig, VerifyingKey as EdVk};
                use signature::Verifier as _;

                if token.signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
                    return Err(DpopError::InvalidSignature);
                }

                let verifying_key: EdVk = crate::jwk::verifying_key_from_okp_ed25519(x)?;
                let signature = EdSig::from_slice(&token.signature_bytes)
                    .map_err(|_| DpopError::InvalidSignature)?;
                verifying_key
                    .verify(token.signing_input.as_bytes(), &signature)
                    .map_err(|_| DpopError::InvalidSignature)?;
                crate::jwk::thumbprint_okp_ed25519(x)?
            }

            ("EdDSA", _) => return Err(DpopError::BadJwk("expect OKP/Ed25519 for EdDSA")),
            ("ES256", _) => return Err(DpopError::BadJwk("expect EC/P-256 for ES256")),
            ("none", _) => return Err(DpopError::InvalidAlg("none".into())),
            (a, _) if a.starts_with("HS") => return Err(DpopError::InvalidAlg(a.into())),
            (other, _) => return Err(DpopError::UnsupportedAlg(other.into())),
        };

        Ok(jkt)
    }

    /// Validate HTTP method and URI binding
    fn validate_http_binding(
        &self,
        claims: &DpopClaims,
        expected_htm: &str,
        expected_htu: &str,
    ) -> Result<(String, String), DpopError> {
        // Strict method & URI checks (normalize both sides, then exact compare)
        let expected_htm_normalized = normalize_method(expected_htm)?;
        let actual_htm_normalized = normalize_method(&claims.htm)?;
        if actual_htm_normalized != expected_htm_normalized {
            return Err(DpopError::HtmMismatch);
        }

        let expected_htu_normalized = normalize_htu(expected_htu)?;
        let actual_htu_normalized = normalize_htu(&claims.htu)?;
        if actual_htu_normalized != expected_htu_normalized {
            return Err(DpopError::HtuMismatch(
                actual_htu_normalized,
                expected_htu_normalized,
            ));
        }

        Ok((expected_htm_normalized, expected_htu_normalized))
    }

    /// Validate access token hash binding
    fn validate_access_token_binding(
        &self,
        claims: &DpopClaims,
        access_token: &str,
    ) -> Result<(), DpopError> {
        // Compute expected SHA-256 bytes of the exact token octets
        let expected_hash = Sha256::digest(access_token.as_bytes());

        // Decode provided ath (must be base64url no-pad)
        let ath_b64 = claims.ath.as_ref().ok_or(DpopError::MissingAth)?;
        let actual_hash = B64
            .decode(ath_b64.as_bytes())
            .map_err(|_| DpopError::AthMalformed)?;

        // Constant-time compare of raw digests
        if actual_hash.len() != expected_hash.len()
            || !bool::from(actual_hash.ct_eq(&expected_hash[..]))
        {
            return Err(DpopError::AthMismatch);
        }

        Ok(())
    }

    /// Check timestamp freshness with configured limits
    fn check_timestamp_freshness(&self, iat: i64) -> Result<(), DpopError> {
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        if iat > current_time + self.options.future_skew_seconds {
            return Err(DpopError::FutureSkew);
        }
        if current_time - iat > self.options.max_age_seconds {
            return Err(DpopError::Stale);
        }
        Ok(())
    }

    /// Validate nonce if required by configuration
    fn validate_nonce_if_required(
        &self,
        claims: &DpopClaims,
        expected_htu_normalized: &str,
        expected_htm_normalized: &str,
        jkt: &str,
        client_binding: Option<&str>,
    ) -> Result<(), DpopError> {
        match &self.options.nonce_mode {
            NonceMode::Disabled => { /* do nothing */ }
            NonceMode::RequireEqual { expected_nonce } => {
                let nonce_value = claims.nonce.as_ref().ok_or(DpopError::MissingNonce)?;
                if nonce_value != expected_nonce {
                    let fresh_nonce = expected_nonce.to_string();
                    return Err(DpopError::UseDpopNonce { nonce: fresh_nonce });
                }
            }
            NonceMode::Hmac(config) => {
                let HmacConfig {
                    secret,
                    max_age_seconds,
                    bind_htu_htm,
                    bind_jkt,
                    bind_client,
                } = &config;
                let nonce_value = match &claims.nonce {
                    Some(s) => s.as_str(),
                    None => {
                        // Missing → ask client to retry with nonce
                        let current_time = time::OffsetDateTime::now_utc().unix_timestamp();
                        let nonce_ctx = crate::nonce::NonceCtx {
                            htu: if *bind_htu_htm {
                                Some(expected_htu_normalized)
                            } else {
                                None
                            },
                            htm: if *bind_htu_htm {
                                Some(expected_htm_normalized)
                            } else {
                                None
                            },
                            jkt: if *bind_jkt { Some(jkt) } else { None },
                            client: if *bind_client { client_binding } else { None },
                        };
                        let fresh_nonce =
                            crate::nonce::issue_nonce(secret, current_time, &nonce_ctx)?;
                        return Err(DpopError::UseDpopNonce { nonce: fresh_nonce });
                    }
                };

                let current_time = time::OffsetDateTime::now_utc().unix_timestamp();
                let nonce_ctx = crate::nonce::NonceCtx {
                    htu: if *bind_htu_htm {
                        Some(expected_htu_normalized)
                    } else {
                        None
                    },
                    htm: if *bind_htu_htm {
                        Some(expected_htm_normalized)
                    } else {
                        None
                    },
                    jkt: if *bind_jkt { Some(jkt) } else { None },
                    client: if *bind_client { client_binding } else { None },
                };

                if crate::nonce::verify_nonce(
                    secret,
                    nonce_value,
                    current_time,
                    *max_age_seconds,
                    &nonce_ctx,
                )
                .is_err()
                {
                    // On invalid/stale → emit NEW nonce so client can retry immediately
                    let fresh_nonce = crate::nonce::issue_nonce(secret, current_time, &nonce_ctx)?;
                    return Err(DpopError::UseDpopNonce { nonce: fresh_nonce });
                }
            }
        }
        Ok(())
    }

    /// Prevent replay attacks using the replay store
    async fn prevent_replay<S: ReplayStore + ?Sized>(
        &self,
        store: &mut S,
        jti_hash: JtiHash,
        claims: &DpopClaims,
        jkt: &str,
        client_binding: Option<&str>,
    ) -> Result<(), DpopError> {
        let is_first_use = store
            .insert_once(
                jti_hash.as_array(),
                ReplayContext {
                    jkt: Some(jkt),
                    htm: Some(&claims.htm),
                    htu: Some(&claims.htu),
                    client_id: client_binding,
                    iat: claims.iat,
                },
            )
            .await?;

        if !is_first_use {
            return Err(DpopError::Replay);
        }

        Ok(())
    }
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify DPoP proof and record the jti to prevent replays.
///
/// # Deprecated
/// This function is maintained for backward compatibility. New code should use `DpopVerifier` instead.
/// See the `DpopVerifier` documentation for usage examples.
#[deprecated(since = "2.0.0", note = "Use DpopVerifier instead")]
pub async fn verify_proof<S: ReplayStore + ?Sized>(
    store: &mut S,
    dpop_compact_jws: &str,
    expected_htu: &str,
    expected_htm: &str,
    access_token: Option<&str>,
    opts: VerifyOptions,
) -> Result<VerifiedDpop, DpopError> {
    let verifier = DpopVerifier { options: opts };
    verifier
        .verify(
            store,
            dpop_compact_jws,
            expected_htu,
            expected_htm,
            access_token,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::thumbprint_ec_p256;
    use crate::nonce::issue_nonce;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;
    use secrecy::SecretBox;

    // ---- helpers ----------------------------------------------------------------

    fn gen_es256_key() -> (SigningKey, String, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x_coordinate = B64.encode(encoded_point.x().unwrap());
        let y_coordinate = B64.encode(encoded_point.y().unwrap());
        (signing_key, x_coordinate, y_coordinate)
    }

    fn make_jws(
        signing_key: &SigningKey,
        header_json: serde_json::Value,
        claims_json: serde_json::Value,
    ) -> String {
        let header_bytes = serde_json::to_vec(&header_json).unwrap();
        let payload_bytes = serde_json::to_vec(&claims_json).unwrap();
        let header_b64 = B64.encode(header_bytes);
        let payload_b64 = B64.encode(payload_bytes);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = B64.encode(signature.to_bytes());
        format!("{header_b64}.{payload_b64}.{signature_b64}")
    }

    #[derive(Default)]
    struct MemoryStore(std::collections::HashSet<[u8; 32]>);

    #[async_trait::async_trait]
    impl ReplayStore for MemoryStore {
        async fn insert_once(
            &mut self,
            jti_hash: [u8; 32],
            _ctx: ReplayContext<'_>,
        ) -> Result<bool, DpopError> {
            Ok(self.0.insert(jti_hash))
        }
    }
    // ---- tests ------------------------------------------------------------------
    #[test]
    fn thumbprint_has_expected_length_and_no_padding() {
        // 32 zero bytes -> base64url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (43 chars)
        let x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let y = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let t1 = thumbprint_ec_p256(x, y).expect("thumbprint");
        let t2 = thumbprint_ec_p256(x, y).expect("thumbprint");
        // deterministic and base64url w/out '=' padding; sha256 -> 43 chars
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 43);
        assert!(!t1.contains('='));
    }

    #[test]
    fn decoding_key_rejects_wrong_sizes() {
        // 31-byte x (trimmed), 32-byte y
        let bad_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 31]);
        let good_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let res = crate::jwk::verifying_key_from_p256_xy(&bad_x, &good_y);
        assert!(res.is_err(), "expected error for bad y");

        // 32-byte x, 33-byte y
        let good_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let bad_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 33]);
        let res = crate::jwk::verifying_key_from_p256_xy(&good_x, &bad_y);
        assert!(res.is_err(), "expected error for bad y");
    }

    #[tokio::test]
    async fn replay_store_trait_basic() {
        use async_trait::async_trait;
        use std::collections::HashSet;

        struct MemoryStore(HashSet<[u8; 32]>);

        #[async_trait]
        impl ReplayStore for MemoryStore {
            async fn insert_once(
                &mut self,
                jti_hash: [u8; 32],
                _ctx: ReplayContext<'_>,
            ) -> Result<bool, DpopError> {
                Ok(self.0.insert(jti_hash))
            }
        }

        let mut s = MemoryStore(HashSet::new());
        let first = s
            .insert_once(
                [42u8; 32],
                ReplayContext {
                    jkt: Some("j"),
                    htm: Some("POST"),
                    htu: Some("https://ex"),
                    client_id: None,
                    iat: 0,
                },
            )
            .await
            .unwrap();
        let second = s
            .insert_once(
                [42u8; 32],
                ReplayContext {
                    jkt: Some("j"),
                    htm: Some("POST"),
                    htu: Some("https://ex"),
                    client_id: None,
                    iat: 0,
                },
            )
            .await
            .unwrap();
        assert!(first);
        assert!(!second); // replay detected
    }
    #[tokio::test]
    async fn verify_valid_es256_proof() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j1","iat":now,"htm":"GET","htu":"https://api.example.com/resource"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let res = verify_proof(
            &mut store,
            &jws,
            "https://api.example.com/resource",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await;
        assert!(res.is_ok(), "{res:?}");
    }

    #[tokio::test]
    async fn method_normalization_allows_lowercase_claim() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j2","iat":now,"htm":"get","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        assert!(verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn htu_normalizes_dot_segments_and_default_ports_and_strips_qf() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // claim has :443, dot-segment, query and fragment
        let claim_htu = "https://EX.COM:443/a/../b?q=1#frag";
        let expect_htu = "https://ex.com/b";
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j3","iat":now,"htm":"GET","htu":claim_htu});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        assert!(verify_proof(
            &mut store,
            &jws,
            expect_htu,
            "GET",
            None,
            VerifyOptions::default()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn htu_path_case_mismatch_fails() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j4","iat":now,"htm":"GET","htu":"https://ex.com/API"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/api",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::HtuMismatch);
    }

    #[tokio::test]
    async fn alg_none_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // still sign, but "alg":"none" must be rejected before/independent of signature
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"none","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j5","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidAlg(_));
    }

    #[tokio::test]
    async fn alg_hs256_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j6","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidAlg(_));
    }

    #[tokio::test]
    async fn jwk_with_private_d_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // inject "d" (any string) -> must be rejected
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y,"d":"AAAA"}});
        let p = serde_json::json!({"jti":"j7","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::BadJwk(_));
    }

    #[tokio::test]
    async fn ath_binding_ok_and_mismatch_and_padded_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let at = "access.token.string";
        let ath = B64.encode(Sha256::digest(at.as_bytes()));
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});

        // OK
        let p_ok = serde_json::json!({"jti":"j8","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath});
        let jws_ok = make_jws(&sk, h.clone(), p_ok);
        let mut store = MemoryStore::default();
        assert!(verify_proof(
            &mut store,
            &jws_ok,
            "https://ex.com/a",
            "GET",
            Some(at),
            VerifyOptions::default()
        )
        .await
        .is_ok());

        // Mismatch
        let p_bad = serde_json::json!({"jti":"j9","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath});
        let jws_bad = make_jws(&sk, h.clone(), p_bad);
        let mut store2 = MemoryStore::default();
        let err = verify_proof(
            &mut store2,
            &jws_bad,
            "https://ex.com/a",
            "GET",
            Some("different.token"),
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::AthMismatch);

        // Padded ath should be rejected as malformed (engine is URL_SAFE_NO_PAD)
        let ath_padded = format!("{ath}==");
        let p_pad = serde_json::json!({"jti":"j10","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath_padded});
        let jws_pad = make_jws(&sk, h.clone(), p_pad);
        let mut store3 = MemoryStore::default();
        let err = verify_proof(
            &mut store3,
            &jws_pad,
            "https://ex.com/a",
            "GET",
            Some(at),
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::AthMalformed);
    }

    #[tokio::test]
    async fn freshness_future_skew_and_stale() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});

        // Future skew just over limit
        let future_skew_seconds = 5;
        let p_future = serde_json::json!({
            "jti":"jf",
            "iat":now + future_skew_seconds + 5,
            "htm":"GET",
            "htu":"https://ex.com/a"
        });
        let jws_future = make_jws(&sk, h.clone(), p_future);
        let mut store1 = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds,
            nonce_mode: NonceMode::Disabled,
            client_binding: None,
        };
        let err = verify_proof(
            &mut store1,
            &jws_future,
            "https://ex.com/a",
            "GET",
            None,
            opts,
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::FutureSkew);

        // Stale just over limit
        let p_stale =
            serde_json::json!({"jti":"js","iat":now - 301,"htm":"GET","htu":"https://ex.com/a"});
        let jws_stale = make_jws(&sk, h.clone(), p_stale);
        let mut store2 = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds,
            nonce_mode: NonceMode::Disabled,
            client_binding: None,
        };
        let err = verify_proof(
            &mut store2,
            &jws_stale,
            "https://ex.com/a",
            "GET",
            None,
            opts,
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::Stale);
    }

    #[tokio::test]
    async fn replay_same_jti_is_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jr","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let ok1 = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await;
        assert!(ok1.is_ok());
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::Replay);
    }

    #[tokio::test]
    async fn signature_tamper_detected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jt","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let mut jws = make_jws(&sk, h, p);

        // Flip one byte in the payload section (keep base64url valid length)
        let bytes = unsafe { jws.as_bytes_mut() }; // alternative: rebuild string
                                                   // Find the second '.' and flip a safe ASCII char before it
        let mut dot_count = 0usize;
        for i in 0..bytes.len() {
            if bytes[i] == b'.' {
                dot_count += 1;
                if dot_count == 2 && i > 10 {
                    bytes[i - 5] ^= 0x01; // tiny flip
                    break;
                }
            }
        }

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidSignature);
    }

    #[tokio::test]
    async fn method_mismatch_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jm","iat":now,"htm":"POST","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::HtmMismatch);
    }

    #[test]
    fn normalize_helpers_examples() {
        // sanity checks for helpers used by verify_proof
        assert_eq!(
            normalize_htu("https://EX.com:443/a/./b/../c?x=1#frag").unwrap(),
            "https://ex.com/a/c"
        );
        assert_eq!(normalize_method("get").unwrap(), "GET");
        assert!(normalize_method("CUSTOM").is_err());
    }

    #[tokio::test]
    async fn jti_too_long_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let too_long = "x".repeat(513);
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":too_long,"iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::JtiTooLong);
    }
    // ----------------------- Nonce: RequireEqual -------------------------------

    #[tokio::test]
    async fn nonce_require_equal_ok() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let expected_nonce = "nonce-123";
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-reqeq-ok",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": expected_nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::RequireEqual {
                expected_nonce: expected_nonce.to_string(),
            },
            client_binding: None,
        };
        assert!(
            verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn nonce_require_equal_missing_claim() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-reqeq-miss",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::RequireEqual {
                expected_nonce: "x".into(),
            },
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::MissingNonce);
    }

    #[tokio::test]
    async fn nonce_require_equal_mismatch_yields_usedpopnonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let claim_nonce = "client-value";
        let expected_nonce = "server-expected";
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-reqeq-mis",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": claim_nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::RequireEqual {
                expected_nonce: expected_nonce.into(),
            },
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        // Server should respond with UseDpopNonce carrying a fresh/expected nonce
        if let DpopError::UseDpopNonce { nonce } = err {
            assert_eq!(nonce, expected_nonce);
        } else {
            panic!("expected UseDpopNonce, got {err:?}");
        }
    }

    // -------------------------- Nonce: HMAC ------------------------------------

    #[tokio::test]
    async fn nonce_hmac_ok_bound_all() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        // Compute jkt from header jwk x/y to match verifier's jkt
        let jkt = thumbprint_ec_p256(&x, &y).unwrap();

        let secret = SecretBox::from(b"supersecret".to_vec());
        let ctx = crate::nonce::NonceCtx {
            htu: Some(expected_htu),
            htm: Some(expected_htm),
            jkt: Some(&jkt),
            client: None,
        };
        let nonce = issue_nonce(&secret, now, &ctx).expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-ok",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        assert!(
            verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn nonce_hmac_missing_claim_prompts_use_dpop_nonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let secret = SecretBox::from(b"supersecret".to_vec());

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-miss",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::UseDpopNonce { .. });
    }

    #[tokio::test]
    async fn nonce_hmac_wrong_htu_prompts_use_dpop_nonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htm = "GET";
        let expected_htu = "https://ex.com/correct";

        // Bind nonce to a different HTU to force mismatch
        let jkt = thumbprint_ec_p256(&x, &y).unwrap();
        let secret = SecretBox::from(b"k".to_vec());
        let ctx_wrong = crate::nonce::NonceCtx {
            htu: Some("https://ex.com/wrong"),
            htm: Some(expected_htm),
            jkt: Some(&jkt),
            client: None,
        };
        let nonce = issue_nonce(&secret, now, &ctx_wrong).expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-htu-mis",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::UseDpopNonce { .. });
    }

    #[tokio::test]
    async fn nonce_hmac_wrong_jkt_prompts_use_dpop_nonce() {
        // Create two keys; mint nonce with jkt from key A, but sign proof with key B
        let (_sk_a, x_a, y_a) = gen_es256_key();
        let (sk_b, x_b, y_b) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let jkt_a = thumbprint_ec_p256(&x_a, &y_a).unwrap();
        let secret = SecretBox::from(b"secret-2".to_vec());
        let ctx = crate::nonce::NonceCtx {
            htu: Some(expected_htu),
            htm: Some(expected_htm),
            jkt: Some(&jkt_a), // bind nonce to A's jkt
            client: None,
        };
        let nonce = issue_nonce(&secret, now, &ctx).expect("issue_nonce");

        // Build proof with key B (=> jkt != jkt_a)
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x_b,"y":y_b}});
        let p = serde_json::json!({
            "jti":"n-hmac-jkt-mis",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk_b, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::UseDpopNonce { .. });
    }

    #[tokio::test]
    async fn nonce_hmac_stale_prompts_use_dpop_nonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let jkt = thumbprint_ec_p256(&x, &y).unwrap();
        let secret = SecretBox::from(b"secret-3".to_vec());
        // Issue with ts older than max_age
        let issued_ts = now - 400;
        let nonce = issue_nonce(
            &secret,
            issued_ts,
            &crate::nonce::NonceCtx {
                htu: Some(expected_htu),
                htm: Some(expected_htm),
                jkt: Some(&jkt),
                client: None,
            },
        )
        .expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-stale",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::UseDpopNonce { .. });
    }

    #[tokio::test]
    async fn nonce_hmac_future_skew_prompts_use_dpop_nonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";

        let jkt = thumbprint_ec_p256(&x, &y).unwrap();
        let secret = SecretBox::from(b"secret-4".to_vec());
        // Issue with ts in the future beyond 5s tolerance
        let issued_ts = now + 10;
        let nonce = issue_nonce(
            &secret,
            issued_ts,
            &crate::nonce::NonceCtx {
                htu: Some(expected_htu),
                htm: Some(expected_htm),
                jkt: Some(&jkt),
                client: None,
            },
        )
        .expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-future",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, false)),
            client_binding: None,
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        matches!(err, DpopError::UseDpopNonce { .. });
    }

    #[tokio::test]
    async fn nonce_hmac_client_binding_ok() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";
        let client_id = "client-123";

        let jkt = thumbprint_ec_p256(&x, &y).unwrap();
        let secret = SecretBox::from(b"secret-client".to_vec());
        let ctx = crate::nonce::NonceCtx {
            htu: Some(expected_htu),
            htm: Some(expected_htm),
            jkt: Some(&jkt),
            client: Some(client_id),
        };
        let nonce = issue_nonce(&secret, now, &ctx).expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-client-ok",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, true)),
            client_binding: Some(ClientBinding::new(client_id)),
        };
        assert!(
            verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn nonce_hmac_client_binding_mismatch_prompts_use_dpop_nonce() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";
        let issue_client_id = "client-issuer";
        let verify_client_id = "client-verifier";

        let jkt = thumbprint_ec_p256(&x, &y).unwrap();
        let secret = SecretBox::from(b"secret-client-mismatch".to_vec());
        let ctx = crate::nonce::NonceCtx {
            htu: Some(expected_htu),
            htm: Some(expected_htm),
            jkt: Some(&jkt),
            client: Some(issue_client_id),
        };
        let nonce = issue_nonce(&secret, now, &ctx).expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-client-mismatch",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret, 300, true, true, true)),
            client_binding: Some(ClientBinding::new(verify_client_id)),
        };
        let err = verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
            .await
            .unwrap_err();
        if let DpopError::UseDpopNonce { nonce: new_nonce } = err {
            // Response nonce should be bound to the verifier's client binding
            let retry_ctx = crate::nonce::NonceCtx {
                htu: Some(expected_htu),
                htm: Some(expected_htm),
                jkt: Some(&jkt),
                client: Some(verify_client_id),
            };
            assert!(
                crate::nonce::verify_nonce(&secret, &new_nonce, now, 300, &retry_ctx).is_ok(),
                "returned nonce should bind to verifier client id"
            );
        } else {
            panic!("expected UseDpopNonce, got {err:?}");
        }
    }

    #[tokio::test]
    async fn nonce_hmac_constructor_with_non_boxed_types() {
        // Test that HmacConfig::new() works with non-boxed types
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expected_htu = "https://ex.com/a";
        let expected_htm = "GET";
        let jkt = thumbprint_ec_p256(&x, &y).unwrap();

        // Test with byte array (b"..." syntax)
        let secret_bytes = b"test-secret-bytes";
        let ctx = crate::nonce::NonceCtx {
            htu: Some(expected_htu),
            htm: Some(expected_htm),
            jkt: Some(&jkt),
            client: None,
        };
        let nonce = crate::nonce::issue_nonce(secret_bytes, now, &ctx).expect("issue_nonce");

        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({
            "jti":"n-hmac-constructor-test",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce
        });
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        // Use the new constructor with a byte array directly (no .as_slice() needed!)
        let opts = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(secret_bytes, 300, true, true, false)),
            client_binding: None,
        };
        assert!(
            verify_proof(&mut store, &jws, expected_htu, expected_htm, None, opts)
                .await
                .is_ok()
        );

        // Test with Vec<u8>
        let secret_vec = b"test-secret-vec".to_vec();
        let nonce2 = crate::nonce::issue_nonce(&secret_vec, now, &ctx).expect("issue_nonce");
        let p2 = serde_json::json!({
            "jti":"n-hmac-constructor-test-2",
            "iat":now,
            "htm":expected_htm,
            "htu":expected_htu,
            "nonce": nonce2
        });
        let jws2 = make_jws(
            &sk,
            serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}}),
            p2,
        );
        let mut store2 = MemoryStore::default();
        let opts2 = VerifyOptions {
            max_age_seconds: 300,
            future_skew_seconds: 5,
            nonce_mode: NonceMode::Hmac(HmacConfig::new(&secret_vec, 300, true, true, false)),
            client_binding: None,
        };
        assert!(
            verify_proof(&mut store2, &jws2, expected_htu, expected_htm, None, opts2)
                .await
                .is_ok()
        );
    }

    #[cfg(feature = "eddsa")]
    mod eddsa_tests {
        use super::*;
        use ed25519_dalek::Signer;
        use ed25519_dalek::{Signature as EdSig, SigningKey as EdSk, VerifyingKey as EdVk};
        use rand_core::OsRng;

        fn gen_ed25519() -> (EdSk, String) {
            let sk = EdSk::generate(&mut OsRng);
            let vk = EdVk::from(&sk);
            let x_b64 = B64.encode(vk.as_bytes()); // 32-byte public key
            (sk, x_b64)
        }

        fn make_jws_ed(sk: &EdSk, header: serde_json::Value, claims: serde_json::Value) -> String {
            let h = serde_json::to_vec(&header).unwrap();
            let p = serde_json::to_vec(&claims).unwrap();
            let h_b64 = B64.encode(h);
            let p_b64 = B64.encode(p);
            let signing_input = format!("{h_b64}.{p_b64}");
            let sig: EdSig = sk.sign(signing_input.as_bytes());
            let s_b64 = B64.encode(sig.to_bytes());
            format!("{h_b64}.{p_b64}.{s_b64}")
        }

        #[tokio::test]
        async fn verify_valid_eddsa_proof() {
            let (sk, x) = gen_ed25519();
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let h = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":x}});
            let p =
                serde_json::json!({"jti":"ed-ok","iat":now,"htm":"GET","htu":"https://ex.com/a"});
            let jws = make_jws_ed(&sk, h, p);

            let mut store = super::MemoryStore::default();
            assert!(verify_proof(
                &mut store,
                &jws,
                "https://ex.com/a",
                "GET",
                None,
                VerifyOptions::default(),
            )
            .await
            .is_ok());
        }

        #[tokio::test]
        async fn eddsa_wrong_jwk_type_rejected() {
            let (sk, x) = gen_ed25519();
            let now = OffsetDateTime::now_utc().unix_timestamp();
            // bad: kty/crv don't match EdDSA expectations
            let h = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"EC","crv":"P-256","x":x,"y":x}});
            let p = serde_json::json!({"jti":"ed-badjwk","iat":now,"htm":"GET","htu":"https://ex.com/a"});
            let jws = make_jws_ed(&sk, h, p);

            let mut store = super::MemoryStore::default();
            let err = verify_proof(
                &mut store,
                &jws,
                "https://ex.com/a",
                "GET",
                None,
                VerifyOptions::default(),
            )
            .await
            .unwrap_err();
            matches!(err, DpopError::BadJwk(_));
        }

        #[tokio::test]
        async fn eddsa_signature_tamper_detected() {
            let (sk, x) = gen_ed25519();
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let h = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":x}});
            let p = serde_json::json!({"jti":"ed-tamper","iat":now,"htm":"GET","htu":"https://ex.com/a"});
            let mut jws = make_jws_ed(&sk, h, p);
            // flip a byte in the header part (remain base64url-ish length)
            unsafe {
                let bytes = jws.as_bytes_mut();
                for i in 10..(bytes.len().min(40)) {
                    bytes[i] ^= 1;
                    break;
                }
            }
            let mut store = super::MemoryStore::default();
            let err = verify_proof(
                &mut store,
                &jws,
                "https://ex.com/a",
                "GET",
                None,
                VerifyOptions::default(),
            )
            .await
            .unwrap_err();
            matches!(err, DpopError::InvalidSignature);
        }
    }
}

//! HKDF key derivation: derive separate auth and signing keys from a shared master token.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

const AUTH_INFO: &[u8] = b"cloakcat-auth-v1";
const SIGN_INFO: &[u8] = b"cloakcat-sign-v1";

/// Keys derived from a single master token via HKDF-SHA256.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Used for X-Agent-Token authentication.
    pub auth_key: [u8; 32],
    /// Used for HMAC-SHA256 result signing.
    pub signing_key: [u8; 32],
}

impl DerivedKeys {
    /// Derive auth and signing keys from the master token bytes.
    pub fn from_master(master: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, master);

        let mut auth_key = [0u8; 32];
        hk.expand(AUTH_INFO, &mut auth_key)
            .expect("32 bytes is valid for HKDF-SHA256");

        let mut signing_key = [0u8; 32];
        hk.expand(SIGN_INFO, &mut signing_key)
            .expect("32 bytes is valid for HKDF-SHA256");

        Self {
            auth_key,
            signing_key,
        }
    }

    /// Base64-encoded auth key (used as X-Agent-Token header value on the wire).
    pub fn auth_token(&self) -> String {
        B64.encode(self.auth_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let k1 = DerivedKeys::from_master(b"my-secret-token-1234");
        let k2 = DerivedKeys::from_master(b"my-secret-token-1234");
        assert_eq!(k1.auth_key, k2.auth_key);
        assert_eq!(k1.signing_key, k2.signing_key);
    }

    #[test]
    fn auth_and_signing_keys_differ() {
        let k = DerivedKeys::from_master(b"my-secret-token-1234");
        assert_ne!(k.auth_key, k.signing_key);
    }

    #[test]
    fn different_master_different_keys() {
        let k1 = DerivedKeys::from_master(b"token-aaa");
        let k2 = DerivedKeys::from_master(b"token-bbb");
        assert_ne!(k1.auth_key, k2.auth_key);
        assert_ne!(k1.signing_key, k2.signing_key);
    }

    #[test]
    fn auth_token_is_base64() {
        let k = DerivedKeys::from_master(b"my-secret-token-1234");
        let token = k.auth_token();
        let decoded = B64.decode(&token).expect("should be valid base64");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), &k.auth_key);
    }
}

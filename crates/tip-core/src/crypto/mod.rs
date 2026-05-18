use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use rand_core::OsRng;

use crate::ports::{CryptoError, Signer, Verifier};

#[derive(Clone)]
pub struct Ed25519Keypair {
    signing_key: SigningKey,
}

#[derive(Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Keypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed_base64(seed: &str) -> Result<Self, CryptoError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(seed)
            .map_err(|err| CryptoError::InvalidKey(err.to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Ed25519 seed must be 32 bytes".into()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn seed_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes())
    }
}

impl Signer for Ed25519Keypair {
    fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<String, CryptoError> {
        use ed25519_dalek::Signer as DalekSigner;
        let signature = self.signing_key.sign(message);
        Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, public_key: &str, message: &[u8], signature: &str) -> Result<(), CryptoError> {
        let public_key = decode_array::<32>(public_key)
            .map_err(|err| CryptoError::InvalidKey(err.to_string()))?;
        let signature = decode_array::<64>(signature)
            .map_err(|err| CryptoError::InvalidSignature(err.to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|err| CryptoError::InvalidKey(err.to_string()))?;
        let signature = Signature::from_bytes(&signature);

        verifying_key
            .verify(message, &signature)
            .map_err(|err| CryptoError::InvalidSignature(err.to_string()))
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| err.to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("expected {} bytes", N))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_signatures_round_trip() {
        let keypair = Ed25519Keypair::generate();
        let verifier = Ed25519Verifier;
        let message = b"tip-test";
        let signature = keypair.sign(message).unwrap();

        verifier
            .verify(&keypair.public_key(), message, &signature)
            .unwrap();
    }
}

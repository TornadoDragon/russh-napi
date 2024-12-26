use crate::error::WrappedError;
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use russh_keys::{HashAlg, PublicKeyBase64};

#[napi]
#[derive(Clone)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<HashAlgorithm> for Option<HashAlg> {
    fn from(value: HashAlgorithm) -> Self {
        match value {
            HashAlgorithm::Sha1 => None,
            HashAlgorithm::Sha256 => Some(HashAlg::Sha256),
            HashAlgorithm::Sha512 => Some(HashAlg::Sha512),
        }
    }
}

#[napi]
#[derive(Clone)]
pub struct SshPublicKey {
    inner: russh_keys::PublicKey,
}

#[napi]
impl SshPublicKey {
    #[napi]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm().to_string()
    }

    #[napi]
    pub fn fingerprint(&self) -> String {
        format!("{}", self.inner.fingerprint(HashAlg::Sha256))
    }

    #[napi]
    pub fn base64(&self) -> String {
        self.inner.public_key_base64()
    }

    #[napi]
    pub fn bytes(&self) -> Uint8Array {
        self.inner.public_key_bytes().into()
    }
}

impl From<russh_keys::PublicKey> for SshPublicKey {
    fn from(inner: russh_keys::PublicKey) -> Self {
        SshPublicKey { inner }
    }
}

#[napi]
#[derive(Clone)]
pub struct SshKeyPair {
    pub(crate) inner: russh_keys::PrivateKey,
}

#[napi]
impl SshKeyPair {
    #[napi]
    pub fn public_key(&self) -> SshPublicKey {
        self.inner.public_key().clone().into()
    }
}

#[napi]
pub fn parse_key(data: String, password: Option<String>) -> napi::Result<SshKeyPair> {
    russh_keys::decode_secret_key(&data, password.as_deref())
        .map_err(|e| WrappedError::from(russh::Error::from(e)).into())
        .map(|key| SshKeyPair { inner: key })
}

#[napi]
pub fn is_pageant_running() -> bool {
    #[cfg(windows)]
    return pageant::is_pageant_running();

    #[cfg(unix)]
    false
}

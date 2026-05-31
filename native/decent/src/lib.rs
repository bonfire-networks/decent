use std::io::BufReader;

use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use rand::thread_rng;
use rustler::types::binary::OwnedBinary;
use rustler::NifResult;
use rustler::{Encoder, Env, Term};

use pgp::errors::Error as PgpLibError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PgpError {
    #[error("Invalid public key format")]
    InvalidPublicKeyFormat,
    #[error("Invalid private key format")]
    InvalidPrivateKeyFormat,
    #[error("Encryption failed: {0}")]
    EncryptionError(#[from] PgpLibError),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
}

mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Parses a public key from any supported format (single armored, armored keychain,
/// or raw binary packets) and returns the first usable key.
fn find_encryption_key(public_key: &[u8]) -> Result<SignedPublicKey, PgpError> {
    // 1. Try single armored key
    if let Ok((k, _)) = SignedPublicKey::from_armor_single(BufReader::new(public_key)) {
        return Ok(k);
    }
    // 2. Try armored keychain — from_armor_many returns (iterator, headers)
    if let Ok((iter, _)) = SignedPublicKey::from_armor_many(BufReader::new(public_key)) {
        if let Some(k) = iter.filter_map(|r| r.ok()).next() {
            return Ok(k);
        }
    }
    // 3. Try raw binary OpenPGP packets — from_bytes_many returns Result<Box<iterator>>
    SignedPublicKey::from_bytes_many(BufReader::new(public_key))
        .ok()
        .and_then(|iter| iter.filter_map(|r| r.ok()).next())
        .ok_or(PgpError::InvalidPublicKeyFormat)
}

/// Extracts the first usable public key from a keychain (armored or binary) and
/// returns it as a normalized ASCII-armored string. Use this to normalize keys
/// before caching so cached keys are always a single clean armored block.
pub fn extract_key_internal(public_key: &[u8]) -> Result<Vec<u8>, PgpError> {
    let key = find_encryption_key(public_key)?;
    key.to_armored_bytes(Default::default())
        .map_err(PgpError::EncryptionError)
}

/// Encrypts a message using the recipient's public key provided as a byte slice.
pub fn encrypt_internal(message: &str, public_key: &[u8]) -> Result<Vec<u8>, PgpError> {
    let public_key = find_encryption_key(public_key)?;
    let mut rng = thread_rng();

    let mut builder = MessageBuilder::from_bytes("msg", message.as_bytes().to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(&mut rng, &public_key)
        .map_err(PgpError::EncryptionError)?;

    builder
        .to_armored_string(rng, Default::default())
        .map(|s| s.into_bytes())
        .map_err(PgpError::EncryptionError)
}

/// Decrypts an encrypted message using the recipient's private key provided as a byte slice.
pub fn decrypt_internal(
    encrypted_message: &[u8],
    private_key: &[u8],
    private_key_passphrase: Option<&str>,
) -> Result<String, PgpError> {
    let (private_key, _) = SignedSecretKey::from_armor_single(BufReader::new(private_key))
        .map_err(|_| PgpError::InvalidPrivateKeyFormat)?;

    let password: Password = match private_key_passphrase {
        Some(pp) => pp.into(),
        None => Password::empty(),
    };

    let (message, _) =
        Message::from_armor(BufReader::new(encrypted_message)).map_err(|_| {
            PgpError::DecryptionError("Invalid encrypted data".to_string())
        })?;

    let mut decrypted = message.decrypt(&password, &private_key).map_err(|e| {
        match e {
            PgpLibError::MissingKey | PgpLibError::MdcError => {
                PgpError::DecryptionError("incorrect or missing passphrase or key".to_string())
            }
            _ => PgpError::DecryptionError(format!("{:?}", e)),
        }
    })?;

    decrypted
        .as_data_string()
        .map_err(|e| PgpError::DecryptionError(format!("{:?}", e)))
}

#[rustler::nif]
fn encrypt<'a>(
    env: Env<'a>,
    message: &str,
    public_key: rustler::types::Binary<'a>,
) -> NifResult<Term<'a>> {
    match encrypt_internal(message, public_key.as_slice()) {
        Ok(encrypted) => {
            let mut owned_binary = OwnedBinary::new(encrypted.len()).unwrap();
            owned_binary.as_mut_slice().copy_from_slice(&encrypted);
            Ok((
                atoms::ok(),
                rustler::types::Binary::from_owned(owned_binary, env),
            )
                .encode(env))
        }
        Err(e) => Ok((atoms::error(), e.to_string()).encode(env)),
    }
}

#[rustler::nif]
fn decrypt<'a>(
    env: Env<'a>,
    encrypted_message: rustler::types::Binary<'a>,
    private_key: rustler::types::Binary<'a>,
    private_key_passphrase: Option<&str>,
) -> NifResult<Term<'a>> {
    match decrypt_internal(
        encrypted_message.as_slice(),
        private_key.as_slice(),
        private_key_passphrase,
    ) {
        Ok(decrypted) => Ok((atoms::ok(), decrypted).encode(env)),
        Err(e) => Ok((atoms::error(), e.to_string()).encode(env)),
    }
}

#[rustler::nif]
fn extract_key<'a>(
    env: Env<'a>,
    public_key: rustler::types::Binary<'a>,
) -> NifResult<Term<'a>> {
    match extract_key_internal(public_key.as_slice()) {
        Ok(armored) => {
            let mut owned = OwnedBinary::new(armored.len()).unwrap();
            owned.as_mut_slice().copy_from_slice(&armored);
            Ok((atoms::ok(), rustler::types::Binary::from_owned(owned, env)).encode(env))
        }
        Err(e) => Ok((atoms::error(), e.to_string()).encode(env)),
    }
}

rustler::init!("Elixir.Decent.Native");

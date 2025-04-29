use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};

pub fn aes_encrypt_text(plaintext: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // returns Encrypted password, nonce
    let AES_KEY = std::env::var("AES_KEY").unwrap();
    let key = Key::<Aes256Gcm>::from_slice(AES_KEY.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("Could not encrypt"))?;

    Ok((ciphertext, nonce.to_vec()))
}

pub fn aes_decrypt_text(ciphertext: &[u8], nonce: &[u8]) -> anyhow::Result<String> {
    let AES_KEY = std::env::var("AES_KEY").unwrap();
    let key = Key::<Aes256Gcm>::from_slice(AES_KEY.as_bytes());
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Could not encrypt"))?;

    Ok(String::from_utf8_lossy(&plaintext).to_string())
}
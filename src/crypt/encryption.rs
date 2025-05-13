use rand::{distr::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

pub fn create_reset_token() -> String {
    let s: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

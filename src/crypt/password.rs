pub fn hash_password(raw_password: &str) -> String {
    password_auth::generate_hash(raw_password)
}

pub fn verify_password(raw_password: &str, hash: &str) -> anyhow::Result<()> {
    password_auth::verify_password(raw_password, hash)?;
    Ok(())
}

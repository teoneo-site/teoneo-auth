pub fn hash_password(raw_password: &str) -> String {
    password_auth::generate_hash(raw_password)
}

pub fn verify_password(raw_password: &str, hash: &str) -> anyhow::Result<()> {
    password_auth::verify_password(raw_password, hash)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_password_test() {
        let hashed_password = hash_password("Vladivostok2000");
        verify_password("Vladivostok2000", &hashed_password).unwrap();
    }

    #[test]
    #[should_panic]
    fn verity_incorrec_pwd_test() {
        let hashed_password = hash_password("Vladivostok2000");
        verify_password("Vladivostok3000", &hashed_password).unwrap();
    }
}
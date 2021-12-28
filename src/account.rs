#[derive(Debug, Clone)]
pub struct ChrysalisAccount {
    seed: Vec<u8>,
    mnemonics: String,
}

impl ChrysalisAccount {
    pub fn new() -> Self {
        let mut seed = Vec::new();
        seed.resize(32, 0);
        crypto::utils::rand::fill(&mut seed).unwrap();

        let mnemonics =
            crypto::keys::bip39::wordlist::encode(&seed, &crypto::keys::bip39::wordlist::ENGLISH)
                .unwrap();

        Self { seed, mnemonics }
    }

    pub fn from_mnemonics(mnemonics: &str) -> Result<Self, crypto::keys::bip39::wordlist::Error> {
        let seed = crypto::keys::bip39::wordlist::decode(
            mnemonics,
            &crypto::keys::bip39::wordlist::ENGLISH,
        )?;

        Ok(Self {
            seed,
            mnemonics: mnemonics.to_string(),
        })
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    pub fn mnemonics(&self) -> &str {
        &self.mnemonics
    }
}

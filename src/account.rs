#[derive(Debug, Clone)]
pub struct ChrysalisAccount {
    seed: Vec<u8>,
    mnemonics: String,
}

impl ChrysalisAccount {
    pub fn new() -> Self {
        let mut entropy = [0u8; 32];
        crypto::utils::rand::fill(&mut entropy).unwrap();

        let mnemonics = crypto::keys::bip39::wordlist::encode(
            &entropy,
            &crypto::keys::bip39::wordlist::ENGLISH,
        )
        .unwrap();

        let mut seed = [0u8; 64];
        crypto::keys::bip39::mnemonic_to_seed(&mnemonics, "", &mut seed);

        Self {
            seed: seed.to_vec(),
            mnemonics,
        }
    }

    pub fn from_mnemonics(mnemonics: &str) -> Result<Self, crypto::keys::bip39::wordlist::Error> {
        let mut seed = [0u8; 64];
        crypto::keys::bip39::mnemonic_to_seed(mnemonics, "", &mut seed);

        Ok(Self {
            seed: seed.to_vec(),
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

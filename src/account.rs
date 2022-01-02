#[derive(Debug, Clone)]
pub struct ChrysalisAccount {
    seed: [u8; 64],
    mnemonic: String,
}

impl ChrysalisAccount {
    pub fn new() -> Self {
        let mut entropy = [0u8; 32];
        crypto::utils::rand::fill(&mut entropy).unwrap();

        let mnemonic = crypto::keys::bip39::wordlist::encode(
            &entropy,
            &crypto::keys::bip39::wordlist::ENGLISH,
        )
        .unwrap();

        let mut seed = [0u8; 64];
        crypto::keys::bip39::mnemonic_to_seed(&mnemonic, "", &mut seed);

        Self { seed, mnemonic }
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, crypto::keys::bip39::wordlist::Error> {
        crypto::keys::bip39::wordlist::verify(
            mnemonic.trim(),
            &crypto::keys::bip39::wordlist::ENGLISH,
        )
        .unwrap();

        let mut seed = [0u8; 64];
        crypto::keys::bip39::mnemonic_to_seed(mnemonic.trim(), "", &mut seed);

        Ok(Self {
            seed,
            mnemonic: mnemonic.to_string(),
        })
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
}

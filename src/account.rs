#[derive(Debug, Clone)]
pub struct ChrysalisAccount {
    bech32_address: String,
}

impl ChrysalisAccount {
    pub fn from_bech32_address(address: &str) -> Result<Self, iota_client::bee_message::Error> {
        //validate address
        iota_client::bee_message::address::Address::try_from_bech32(address)?;
        Ok(Self {
            bech32_address: address.to_string(),
        })
    }

    pub fn bech32_target_address(&self) -> &str {
        &self.bech32_address
    }
}

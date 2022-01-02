use iota_legacy::ternary::tryte::TryteBuf;
use log::info;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Debug)]
pub struct Seeds {
    inner: Vec<String>,
}

impl Deref for Seeds {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FromStr for Seeds {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut inner = Vec::new();

        for (i, l) in s.lines().enumerate() {
            // Ignore empty lines
            if l.is_empty() {
                continue;
            }

            let seed_tryte = TryteBuf::try_from_str(l);

            if let Err(err) = seed_tryte {
                // Silently ignore any unrecognized line
                info!("silently ignoring line {}: {}", i + 1, err);
                continue;
            }

            inner.push(seed_tryte.unwrap().to_string());
        }

        Ok(Self { inner })
    }
}

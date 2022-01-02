use iota_legacy::ternary::tryte::TryteBuf;
use log::*;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub addr: String,
    pub idx: usize,
    pub bal: usize,
}

impl FromStr for AddrInfo {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, idx, bal) = {
            let mut iter = s.split_whitespace();
            (iter.next(), iter.next(), iter.next())
        };

        if let (Some(addr), Some(idx), Some(bal)) = (addr, idx, bal) {
            // XXX: TryteBuf is not Clone-able.
            // To make AddrInfo clone-able, we verify it by parsing to TryteBuf,
            // then transforming it back to String.
            let addr_tryte = TryteBuf::try_from_str(addr);
            let idx_usize = idx.parse();
            let bal_usize = bal.parse();

            if addr_tryte.is_err() {
                return Err("failed to parse the first column into a ternary address");
            }

            if idx_usize.is_err() {
                return Err("failed to parse the second column into an index number");
            }

            if idx_usize.is_err() {
                return Err("failed to parse the third column into a balance amount");
            }

            let mut addr_str = addr_tryte.unwrap().to_string();
            // XXX: remove checksum
            addr_str.truncate(81);

            Ok(Self {
                addr: addr_str,
                idx: idx_usize.unwrap(),
                bal: bal_usize.unwrap(),
            })
        } else {
            Err("wrong address info format")
        }
    }
}

#[derive(Debug, Clone)]
pub struct Addrs {
    inner: Vec<AddrInfo>,
}

// impl Addrs {
//     pub fn new() -> Self {
//         Self { inner: Vec::new() }
//     }

//     pub fn from_inner(inner: Vec<AddrInfo>) -> Self {
//         Self { inner }
//     }
// }

impl Deref for Addrs {
    type Target = Vec<AddrInfo>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Addrs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl FromStr for Addrs {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut inner = Vec::new();

        for (i, l) in s.lines().enumerate() {
            match l.parse() {
                Ok(info) => inner.push(info),
                Err(err) => {
                    // Silently ignore any unrecognized line
                    info!("silently ignoring line {}: {}", i + 1, err);
                    continue;
                }
            };
        }

        Ok(Self { inner })
    }
}

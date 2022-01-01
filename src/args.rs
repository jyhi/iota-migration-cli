use clap::{crate_description, crate_name, crate_version, App, AppSettings, Arg};
use std::process;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParallelMode {
    NoParallel,
    ParallelSeeds,
    ParallelSearch,
    ParallelAll,
}

impl ParallelMode {
    pub fn is_parallel_seed(&self) -> bool {
        *self == Self::ParallelSeeds || *self == Self::ParallelAll
    }

    pub fn is_parallel_search(&self) -> bool {
        *self == Self::ParallelSearch || *self == Self::ParallelAll
    }
}

#[derive(Debug, Clone)]
pub struct Args {
    pub legacy_node: String,
    pub chrysalis_node: String,
    pub permanode: String,
    pub mnemonic: Option<String>,
    pub target_account: usize,
    pub target_address: usize,
    pub seeds: String,
    pub addresses: Option<String>,
    pub security_level: u8,
    pub minimum_weight_magnitude: u8,
    pub parallel_mode: ParallelMode,
    pub dry_run: bool,
    pub yes: bool,
}

impl Args {
    pub fn from_cli() -> Self {
        let matches = App::new(crate_name!())
            .version(crate_version!())
            .about(crate_description!())
            .arg(
                Arg::with_name("legacy-node")
                    .long("legacy-node")
                    .takes_value(true)
                    .help("Custom URL to a legacy node"),
            )
            .arg(
                Arg::with_name("chrysalis-node")
                    .long("chrysalis-node")
                    .takes_value(true)
                    .help("Custom URL to a Chrysalis node"),
            )
            .arg(
                Arg::with_name("permanode")
                    .long("permanode")
                    .takes_value(true)
                    .help("Custom URL to a Permanode"),
            )
            .arg(
                Arg::with_name("mnemonic")
                    .long("mnemonic")
                    .takes_value(true)
                    .help("Set a mnemonic of seed on Chrysalis to migrate to"),
            )
            .arg(
                Arg::with_name("target-account")
                    .long("target-account")
                    .takes_value(true)
                    .help("The account index to send migration bundles to"),
            )
            .arg(
                Arg::with_name("target-address")
                    .long("target-address")
                    .takes_value(true)
                    .help("The address index to send migration bundles to"),
            )
            .arg(
                Arg::with_name("seeds")
                    .long("seeds")
                    .short("s")
                    .takes_value(true)
                    .required(true)
                    .help("Where to read the seeds"),
            )
            .arg(
                Arg::with_name("addresses")
                    .long("addresses")
                    .short("a")
                    .takes_value(true)
                    .required(true)
                    .help("Where to read the confirmed addresses"),
            )
            .arg(
                Arg::with_name("security-level")
                    .long("security-level")
                    .short("l")
                    .takes_value(true)
                    .possible_values(&["1", "2", "3"])
                    .help("Security level used in the legacy network"),
            )
            .arg(
                Arg::with_name("minimum-weight-magnitude")
                    .long("minimum-weight-magnitude")
                    .takes_value(true)
                    .help("Custom minimum weight of magnitude"),
            )
            .arg(
                Arg::with_name("parallel-mode")
                    .long("parallel-mode")
                    .takes_value(true)
                    .possible_values(&["seed", "search", "all", "none"])
                    .help("Mode of parallel processing"),
            )
            .arg(
                Arg::with_name("dry-run")
                    .long("dry-run")
                    .short("D")
                    .takes_value(false)
                    .help("Don't actually perform the migration"),
            )
            .arg(
                Arg::with_name("yes")
                    .long("yes")
                    .short("y")
                    .takes_value(false)
                    .help("Gain JoJo power"),
            )
            .setting(AppSettings::ArgRequiredElseHelp)
            .setting(AppSettings::ColoredHelp)
            .get_matches();

        Self {
            legacy_node: matches
                .value_of("legacy-node")
                .unwrap_or(crate::LEGACY_TESTNET_NODE_URL)
                .to_owned(),
            chrysalis_node: matches
                .value_of("chrysalis-node")
                .unwrap_or(crate::CHRYSALIS_TESTNET_NODE_URL)
                .to_owned(),
            permanode: matches
                .value_of("permanode")
                .unwrap_or(crate::PERMANODE_URL)
                .to_owned(),
            mnemonic: match matches.value_of("mnemonic") {
                Some(mnemonic) => {
                    crypto::keys::bip39::wordlist::verify(
                        mnemonic.trim(),
                        &crypto::keys::bip39::wordlist::ENGLISH,
                    )
                    .unwrap();
                    Some(mnemonic.trim().to_owned())
                }
                None => None,
            },
            target_account: match matches.value_of("target-account") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid target account index: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 0, // default
            },
            target_address: match matches.value_of("target-address") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid target address index: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 0, // default
            },
            seeds: matches.value_of("seeds").unwrap().to_owned(),
            addresses: matches.value_of("addresses").map(|x| x.to_owned()),
            security_level: match matches.value_of("security-level") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid security level: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 2, // default
            },
            minimum_weight_magnitude: match matches.value_of("security-level") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid minimum weight of magnitude: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 14, // default
            },
            parallel_mode: match matches.value_of("parallel-mode") {
                Some("seed") => ParallelMode::ParallelSeeds,
                Some("search") => ParallelMode::ParallelSearch,
                Some("all") => ParallelMode::ParallelAll,
                Some("none") => ParallelMode::NoParallel,
                Some(_) => unreachable!(), // clap won't allow any other
                None => ParallelMode::NoParallel,
            },
            dry_run: matches.is_present("dry-run"),
            yes: matches.is_present("yes"),
        }
    }
}

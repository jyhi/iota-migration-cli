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
    pub seeds: String,
    pub addresses: Option<String>,
    pub search: bool,
    pub search_from: usize,
    pub search_to: usize,
    pub gap_limit: usize,
    pub security_level: u8,
    pub mnemonics: Option<String>,
    pub password: String,
    pub legacy_node: String,
    pub chrysalis_node: String,
    pub skip_verification: bool,
    pub parallel_mode: ParallelMode,
    pub chunk_size: usize,
    pub jobs: Option<usize>,
    pub dry_run: bool,
    pub verbose: bool,
    pub yes: bool,
}

impl Args {
    pub fn from_cli() -> Self {
        let matches = App::new(crate_name!())
            .version(crate_version!())
            .about(crate_description!())
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
                    .conflicts_with("search")
                    .help("Where to read the confirmed addresses"),
            )
            .arg(
                Arg::with_name("search")
                    .long("search")
                    .short("S")
                    .takes_value(false)
                    .help(
                        "Whether to generate addresses from the seeds and search for funds in them",
                    ),
            )
            .arg(
                Arg::with_name("search-from")
                    .long("search-from")
                    .short("f")
                    .takes_value(true)
                    .help("Search for addresses starting from the given index"),
            )
            .arg(
                Arg::with_name("search-to")
                    .long("search-to")
                    .short("t")
                    .takes_value(true)
                    .help("Search for address ending at the given index (inclusive)"),
            )
            .arg(
                Arg::with_name("gap-limit")
                    .long("gap-limit")
                    .takes_value(true)
                    .help("Stop if the given number of addresses are empty"),
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
                Arg::with_name("mnemonics")
                    .long("mnemonics")
                    .takes_value(true)
                    .help("Set a mnemonics of seed on Chrysalis to migrate to"),
            )
            .arg(
                Arg::with_name("password")
                    .long("password")
                    .takes_value(true)
                    .help("Set password for the Stronghold storage"),
            )
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
                Arg::with_name("skip-verification")
                    .long("skip-verification")
                    .takes_value(false)
                    .help("Skip address verification when --addresses is supplied"),
            )
            .arg(
                Arg::with_name("parallel-mode")
                    .long("parallel-mode")
                    .takes_value(true)
                    .possible_values(&["seed", "search", "all", "none"])
                    .help("Mode of parallel processing"),
            )
            .arg(
                Arg::with_name("chunk-size")
                    .long("chunk-size")
                    .short("c")
                    .takes_value(true)
                    .help("How many tasks to spawn at a time, if --parallel-mode=search"),
            )
            .arg(
                Arg::with_name("jobs")
                    .long("jobs")
                    .short("j")
                    .takes_value(true)
                    .help("How many threads should be spawned for the migration"),
            )
            .arg(
                Arg::with_name("dry-run")
                    .long("dry-run")
                    .short("D")
                    .takes_value(false)
                    .help("Don't actually perform the migration"),
            )
            .arg(
                Arg::with_name("verbose")
                    .long("verbose")
                    .short("v")
                    .takes_value(false)
                    .help("Be noisy"),
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
            seeds: matches.value_of("seeds").unwrap().to_owned(),
            addresses: matches.value_of("addresses").map(|x| x.to_owned()),
            search: matches.is_present("search"),
            search_from: match matches.value_of("search-from") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid index number to search from: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 0, // default
            },
            search_to: match matches.value_of("search-to") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid index number to search to: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 120, // default
            },
            gap_limit: match matches.value_of("gap-limit") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid gap limit size: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 10, // default
            },
            security_level: match matches.value_of("security-level") {
                Some(x) => x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid security level: {}: {}", e, x);
                    process::exit(1);
                }),
                None => 2, // default
            },
            mnemonics: matches.value_of("mnemonics").map(|s| s.to_owned()),
            password: matches
                .value_of("password")
                .unwrap_or("drowssap")
                .to_owned(),
            legacy_node: matches
                .value_of("legacy-node")
                .unwrap_or(crate::LEGACY_TESTNET_NODE_URL)
                .to_owned(),
            chrysalis_node: matches
                .value_of("chrysalis-node")
                .unwrap_or(crate::CHRYSALIS_TESTNET_NODE_URL)
                .to_owned(),
            skip_verification: matches.is_present("skip-verification"),
            parallel_mode: match matches.value_of("parallel-mode") {
                Some("seed") => ParallelMode::ParallelSeeds,
                Some("search") => ParallelMode::ParallelSearch,
                Some("all") => ParallelMode::ParallelAll,
                Some("none") => ParallelMode::NoParallel,
                Some(_) => unreachable!(), // clap won't allow any other
                None => ParallelMode::NoParallel,
            },
            chunk_size: match matches.value_of("chunk-size") {
                Some(x) => match x.parse() {
                    Ok(parsed) => {
                        // Additionally check if it's > 0
                        if parsed == 0 {
                            eprintln!("Error: chunk size must be larger than zero");
                            process::exit(1);
                        }

                        parsed
                    }
                    Err(e) => {
                        eprintln!("Error: invalid chunk size: {}: {}", e, x);
                        process::exit(1);
                    }
                },
                None => 10, // default
            },
            jobs: matches.value_of("jobs").map(|x| {
                x.parse().unwrap_or_else(|e| {
                    eprintln!("Error: invalid number of jobs specified: {}: {}", e, x);
                    process::exit(1);
                })
            }),
            dry_run: matches.is_present("dry-run"),
            verbose: matches.is_present("verbose"),
            yes: matches.is_present("yes"),
        }
    }
}

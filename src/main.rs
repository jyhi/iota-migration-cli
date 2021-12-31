mod account;
mod addrs;
mod args;
mod seeds;
mod tasks;

use account::ChrysalisAccount;
use addrs::Addrs;
use args::Args;
use log::{debug, error, info, trace};
use rayon::prelude::*;
use seeds::Seeds;
use std::{fs, io, process};

const LEGACY_TESTNET_NODE_URL: &str = "https://nodes-legacy.iotatestmigration6.net";
const CHRYSALIS_TESTNET_NODE_URL: &str = "https://api.lb-0.h.migration6.iotatestmigration6.net";
const PERMANODE_URL: &str = "https://chronicle.iota.org/api";

fn main() {
    env_logger::init();

    let args = Args::from_cli();
    trace!("{:?}", args);

    let seeds: Seeds = match fs::read_to_string(&args.seeds) {
        Ok(s) => match s.parse() {
            Ok(s) => s,
            Err(e) => {
                error!("failed to parse the seeds file: {}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            error!("cannot read seeds from file: {}: {}", e, args.seeds);
            process::exit(e.raw_os_error().unwrap_or(2));
        }
    };

    let num_seeds = seeds.len();
    info!("loaded {} seeds", num_seeds);
    trace!("{:?}", seeds);

    let addrs: Option<Addrs> = if let Some(ref address_file) = args.addresses {
        match fs::read_to_string(address_file) {
            Ok(s) => match s.parse() {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("failed to parse the addresses file: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                error!("cannot read addresses from file: {}: {}", e, address_file);
                process::exit(e.raw_os_error().unwrap_or(2));
            }
        }
    } else {
        None
    };

    let num_addrs = addrs.as_ref().map(|a| a.len()).unwrap_or(0);
    info!("loaded {} addresses", num_addrs);
    trace!("{:?}", addrs);

    // Seeds must be provided, otherwise we can do nothing
    if num_seeds == 0 {
        eprintln!("No seed is loaded, nothing to do!");
        return;
    }

    // Prompt what is to be done
    if num_addrs == 0 {
        // println!(
        //     "Migrating from addresses generated from index {} to index {} for \
        //     each of the {} seed(s).",
        //     args.search_from, args.search_to, num_seeds
        // );
        unimplemented!();
    } else {
        println!(
            "Migrating from the given {} addresses for each of the {} seed(s).\n\
             Legacy Node: {}\n\
             Chrysalis Node: {}",
            num_addrs, num_seeds, args.legacy_node, args.chrysalis_node
        );
    }

    if args.yes {
        eprintln!("Continue? y - specified from command line");
    } else {
        loop {
            eprint!("Continue? [Y/n] ");

            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(n) => {
                    if n == 0 {
                        debug!("user input EOF - exit");
                        return;
                    }
                    let line_lower = line.trim().to_lowercase();
                    if line_lower == "y" || line_lower.is_empty() {
                        debug!("user input {} - continue", line_lower);
                        break;
                    } else if line_lower == "n" {
                        debug!("user input {} - exit", line_lower);
                        return;
                    } else {
                        debug!("user input {} - ask again", line_lower);
                        eprintln!("Please input y or n.");
                        continue;
                    }
                }
                Err(e) => {
                    debug!("{}", e);
                    process::exit(255);
                }
            };
        }
    }

    // Create a new account on Chrysalis - the target to migrate funds to,
    // or use the provided mnemonic
    let chrysalis_account = if let Some(ref mnemonic) = args.mnemonic {
        debug!("using the provided mnemonic for an exiting account on Chrysalis");
        let account = ChrysalisAccount::from_mnemonic(mnemonic);

        if let Err(e) = account {
            error!("failed to use the provided mnemonic: {:?}", e);
            process::exit(1);
        }

        account.unwrap()
    } else {
        debug!("creating an account on Chrysalis");
        let account = ChrysalisAccount::new();

        println!(
            "\n\
             !!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
             !!! New Chrysalis Account !!!\n\
             !!!   SAVE THE MNEMONIC!  !!!\n\
             \n\
             {}\n\
             \n\
             !!!   SAVE THE MNEMONIC!  !!!\n\
             !!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
            ",
            account.mnemonic(),
        );

        account
    };

    // This is the closure to run regardless of parallel or sequential
    let migrate = |seed: &String| {
        debug!("running migration task for seed {}", seed);

        if num_addrs == 0 {
            // No address is provided - generate and migrate
            tasks::search_and_migrate(args.clone(), chrysalis_account.clone(), seed.clone())
        } else {
            // Addresses are provided - just migrate
            tasks::collect_and_migrate(
                args.clone(),
                chrysalis_account.clone(),
                seed.clone(),
                addrs.as_ref().unwrap().clone(),
            )
        }
    };

    let results: Vec<_> = if args.parallel_mode.is_parallel_seed() {
        // Parallel seed processing - every seed will occupy a thread
        debug!("processing each seed in parallel");

        seeds.par_iter().map(migrate).collect()
    } else {
        // Sequential seed processing
        debug!("processing each seed in sequence");

        seeds.iter().map(migrate).collect()
    };

    debug!("{:?}", results);
}

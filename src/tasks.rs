use crate::account::ChrysalisAccount;
use crate::addrs::{AddrInfo, Addrs};
use crate::args::Args;
use bee_ternary::t1b1::T1B1Buf;
use bee_ternary::tryte::TryteBuf;
#[allow(deprecated)]
use crypto::hashes::ternary::kerl::Kerl;
use crypto::keys::ternary::seed::Seed;
#[allow(deprecated)]
use crypto::keys::ternary::wots::sponge::WotsSpongePrivateKeyGeneratorBuilder;
#[allow(deprecated)]
use crypto::keys::ternary::wots::WotsSecurityLevel;
use crypto::keys::ternary::PrivateKeyGenerator;
use crypto::signatures::ternary::PrivateKey;
use crypto::signatures::ternary::PublicKey;
use iota_legacy::client::builder::ClientBuilder as LegacyClientBuilder;
use log::*;
use rayon::prelude::*;
// use iota_legacy::client::builder::Network as LegacyNetwork;
use iota_legacy::client::migration;
use iota_legacy::client::response::InputData;
use iota_legacy::client::AddressInput;
use iota_legacy::client::GetAddressesBuilder;
use iota_legacy::transaction::bundled::{Address, BundledTransactionField};

#[allow(deprecated)]
fn verify_address(seed: String, addr: AddrInfo, security_level: u8) -> Result<AddrInfo, ()> {
    let seed_ternary = Seed::from_trits(
        TryteBuf::try_from_str(&seed)
            .unwrap() // we've validated it during file parsing
            .as_trits()
            .encode::<T1B1Buf>(),
    )
    .unwrap();

    let security_level_wot = match security_level {
        1 => WotsSecurityLevel::Low,
        2 => WotsSecurityLevel::Medium,
        3 => WotsSecurityLevel::High,
        _ => unreachable!(), // this should have been checked during CLI parsing
    };

    let addr_trits = TryteBuf::try_from_str(&addr.addr)
        .unwrap() // we've validated it during file parsing
        .as_trits()
        .encode::<T1B1Buf>();

    let generated_addr = WotsSpongePrivateKeyGeneratorBuilder::<Kerl>::default()
        .with_security_level(security_level_wot)
        .build()
        .unwrap()
        .generate_from_seed(&seed_ternary, addr.idx)
        .unwrap()
        .generate_public_key()
        .unwrap()
        .as_trits()
        .to_owned();

    if addr_trits != generated_addr {
        Err(())
    } else {
        Ok(addr)
    }
}

pub fn search_and_migrate(
    _args: Args,
    _account: ChrysalisAccount,
    _seed: String,
) -> Result<(), ()> {
    error!("search and migrate - not implemented!");
    Err(())
}

pub fn collect_and_migrate(
    args: Args,
    account: ChrysalisAccount,
    seed: String,
    addrs: Addrs,
) -> Result<(), ()> {
    // Tokio asynchronous runtime to wait for asynchronous code in our synchronous code.
    let async_rt = tokio::runtime::Runtime::new().unwrap();

    debug!("seed {}: performing address matches", seed);

    // The task to run below, regardless of parallelism
    let addr_match = |addr: &AddrInfo| {
        if let Ok(matched) = verify_address(seed.clone(), addr.clone(), args.security_level) {
            debug!("seed {}: accept matching address {}", seed, addr.addr);
            Some(matched)
        } else {
            warn!("seed {}: reject mismatched address {}", seed, addr.addr);
            None
        }
    };

    // Match addresses with the given seed. If multiple seeds are in a file and multiple addresses
    // are in a file, then there must be addresses that don't belong to some other seeds. This
    // process filters out any address that doesn't belong to [seed], as this task is only for one
    // seed. [addrs] is moved into and shadowed.
    let addrs: Vec<AddrInfo> = if args.parallel_mode.is_parallel_search() {
        addrs.par_iter().filter_map(addr_match).collect()
    } else {
        addrs.iter().filter_map(addr_match).collect()
    };

    // If all addresses are filtered out, exit early
    if addrs.is_empty() {
        warn!("seed {}: no matching address is accepted! exiting.", seed);
        return Err(());
    }

    // This instance from an older version of iota-client connects to the legacy network.
    let mut legacy_client = LegacyClientBuilder::new()
        .node(&args.legacy_node)
        .unwrap()
        .permanode(&args.permanode)
        .unwrap()
        // .network(LegacyNetwork::Devnet) // ???
        .quorum(true)
        .build()
        .unwrap();

    // This prepared version of address information input is unfortunately required by the legacy
    // client.
    let addrs_prep: Vec<AddressInput> = addrs
        .into_iter()
        .map(|addr| {
            AddressInput {
                address: Address::try_from_inner(
                    // Have to use a legacy bee_ternary because of the legacy client!
                    iota_legacy::ternary::TryteBuf::try_from_str(&addr.addr)
                        .unwrap()
                        .as_trits()
                        .encode(),
                )
                .unwrap(),
                index: addr.idx as u64, // XXX: usize -> u64
                security_lvl: args.security_level,
            }
        })
        .collect();

    // Fetch information from the legacy network. The result here are used for several purposes:
    // 1. Address information verification (against those provided); this is not implemented
    // 2. Input for next steps (the legacy client require exactly this piece of information)
    debug!(
        "seed {}: connecting to the legacy IOTA network to check address information...",
        seed
    );
    let addrs_queried_results = async_rt.block_on(
        legacy_client
            .get_ledger_account_data_for_migration()
            .with_addresses(addrs_prep)
            .finish(),
    );

    // Exit early if there is any error. The resulting tuple is destructed then.
    let (balance, mut input_data, any_spent) = match addrs_queried_results {
        Ok(info) => info,
        Err(err) => {
            error!(
                "seed {}: failed to fetch address information: {}",
                seed, err
            );
            return Err(());
        }
    };

    info!(
        "seed {}: queried total balance {}, {} inputs, {}",
        seed,
        balance,
        input_data.len(),
        if any_spent {
            "some or all have been spent"
        } else {
            "none has been spent"
        }
    );

    // If there isn't any input data, then there's nothing we can do. Exit early.
    if balance == 0 || input_data.is_empty() {
        warn!("seed {}: nothing can be migrated! exiting", seed);
        return Err(());
    }

    // Sort addresses by their balances to ensure that addresses with small balances get bundled
    // together to try avoiding dust inputs.
    debug!("seed {}: sorting addresses by balances", seed);
    input_data.sort_unstable_by_key(|data| data.balance);

    // Bundle address, with every bundle containing at least 1 Mi to go over the dust allowance.
    // FIXME: there is nothing preventing a bundle from having too many inputs (increasing PoW time)
    // XXX: the last bundle doesn't necessarily go beyond the dust allowance
    debug!(
        "seed {}: partitioning addresses into at-least-1-Mi bundles",
        seed
    );
    let bundles: Vec<Vec<InputData>> =
        input_data
            .iter()
            .fold(Vec::new(), |acc: Vec<Vec<InputData>>, data| {
                let mut new_acc = acc.clone();
                let data = data.clone();
                let last = new_acc.pop();

                if let Some(mut last) = last {
                    // Check if the last segment contains at least 1 Mi
                    let last_sum: u64 = last.iter().map(|data| data.balance).sum();

                    if last_sum > 1_000_000 {
                        // Push back the last segment, create a new segment
                        let new = vec![data];
                        new_acc.push(last);
                        new_acc.push(new);
                    } else {
                        // Continue adding into the last segment
                        last.push(data);
                        new_acc.push(last);
                    }
                } else {
                    // This is the first segment, just create and put in
                    let new = vec![data];
                    new_acc.push(new);
                }

                new_acc
            });

    debug!("seed {}: created {} bundles", seed, bundles.len());

    // Bundles that are still dusts need to be filtered out, sorry.
    debug!("seed {}: checking for dusts", seed);
    let (bundles, bundles_dust): (Vec<Vec<InputData>>, Vec<Vec<InputData>>) =
        bundles.into_iter().partition(|bundle| {
            let bundle_balance: u64 = bundle.iter().map(|data| data.balance).sum();

            bundle_balance >= 1_000_000
        });

    if !bundles_dust.is_empty() {
        for bundle_dust in bundles_dust {
            let bundle_dust_summary: Vec<_> = bundle_dust.iter().map(|data| data.index).collect();
            warn!(
                "seed {}: this bundle contains < 1 Mi balance, which is considered as a dust input\
                , and will not be migrated: {:?}",
                seed, bundle_dust_summary
            );
        }
    } else {
        debug!("seed {}: no dust bundle is found", seed);
    }

    // Generate the target address on Chrysalis.
    debug!("seed {}: generating target Chrysalis address...", seed);
    let chrysalis_addr = {
        let generated_addrs = GetAddressesBuilder::new(
            &iota_legacy::client::Seed::from_bytes(account.seed()).unwrap(),
        )
        .with_account_index(args.target_account)
        .with_range(args.target_address..args.target_address + 1)
        .finish()
        .unwrap(); // XXX

        generated_addrs[0]
    };

    // Create (prepare) migration bundles using the migration facilities in the legacy client.
    debug!("seed {}: preparing migration bundles...", seed);
    let bundles_prepared_results = bundles.iter().map(|bundle| {
        async_rt.block_on(migration::create_migration_bundle(
            &legacy_client,
            chrysalis_addr,
            bundle.clone(),
        ))
    }); // avoid using `collect()` when not needed

    // Remove any error.
    let bundles_prepared = bundles_prepared_results.filter_map(|result| {
        match result {
            Ok(bundle) => Some(bundle),
            Err(err) => {
                // FIXME: which bundle?
                error!(
                    "seed {}: failed to create a migration bundle: {}, skipping",
                    seed, err
                );
                None
            }
        }
    }); // avoid using `collect()` when not needed

    // Sign on the migration bundles.
    debug!("seed {}: signing migration bundles...", seed);
    let bundles_signed_results =
        bundles_prepared
            .zip(bundles.iter())
            .map(|(prepared_bundle, input_data)| {
                // This is an older version of [Seed]
                let ternary_seed: iota_legacy::crypto::keys::ternary::seed::Seed =
                    seed.parse().unwrap();

                migration::sign_migration_bundle(ternary_seed, prepared_bundle, input_data.clone())
            });

    // Remove any error.
    let bundles_signed: Vec<_> = bundles_signed_results
        .filter_map(|result| {
            match result {
                Ok(bundle) => Some(bundle),
                Err(err) => {
                    // FIXME: which bundle?
                    error!(
                        "seed {}: failed to sign on a migration bundle: {}, skipping",
                        seed, err
                    );
                    None
                }
            }
        })
        .collect();

    debug!("seed {}: signed {} bundles", seed, bundles_signed.len());

    // Send the migration bundles to the legacy network.
    debug!("seed {}: sending bundles", seed);
    if args.dry_run {
        info!(
            "seed {}: dry-run - pretending that the bundles have been sent successfully",
            seed
        );

        // Print out information about this transaction
        let from_addr_summaries = input_data
            .iter()
            .map(|data| {
                format!(
                    "\n- {}",
                    data.address
                        .to_inner()
                        .encode::<iota_legacy::ternary::T3B1Buf>()
                        .as_trytes()
                        .iter()
                        .fold(String::new(), |mut acc, tryte| {
                            acc.push_str(&tryte.to_string());
                            acc
                        })
                )
            })
            .reduce(|mut acc, summary| {
                acc.push_str(&summary);
                acc
            })
            .unwrap_or_default();

        println!(
            "=== Migration Report ===\n\
             Seed: {}\n\
             From (Legacy IOTA) address(es):{}\n\
             To (Chrysalis) address: {}\n\
             Migration bundle hash(es): (dry-run)\n\
             ========================",
            seed,
            from_addr_summaries,
            bee_message::address::Address::Ed25519(chrysalis_addr).to_bech32("<hrp>"),
        );
    } else {
        let bundles_sent_results = bundles_signed.into_iter().map(|bundle| {
            async_rt.block_on(
                legacy_client
                    .send_trytes()
                    .with_trytes(bundle)
                    .with_min_weight_magnitude(args.minimum_weight_magnitude)
                    .finish(),
            )
        }); // avoid using `collect()` when not needed

        // Remove any error.
        let bundles_sent: Vec<_> = bundles_sent_results
            .filter_map(|result| {
                match result {
                    Ok(bundle) => Some(bundle),
                    Err(err) => {
                        // FIXME: which bundle?
                        error!(
                            "seed {}: failed to send a migration bundle: {}, dropping",
                            seed, err
                        );
                        None
                    }
                }
            })
            .collect();

        // Print out information about this transaction
        let from_addr_summaries = input_data
            .iter()
            .map(|data| {
                format!(
                    "\n- {}",
                    data.address
                        .to_inner()
                        .encode::<iota_legacy::ternary::T3B1Buf>()
                        .as_trytes()
                        .iter()
                        .fold(String::new(), |mut acc, tryte| {
                            acc.push_str(&tryte.to_string());
                            acc
                        })
                )
            })
            .reduce(|mut acc, summary| {
                acc.push_str(&summary);
                acc
            })
            .unwrap_or_default();

        let (bundle_addresses, bundle_hashes) = bundles_sent
            .iter()
            .flatten()
            .map(|bundle| {
                (
                    format!(
                        "\n- {}",
                        bundle
                            .address()
                            .to_inner()
                            .encode::<iota_legacy::ternary::T3B1Buf>()
                            .as_trytes()
                            .iter()
                            .fold(String::new(), |mut acc, tryte| {
                                acc.push_str(&tryte.to_string());
                                acc
                            })
                    ),
                    format!("\n- {}", bundle.bundle()),
                )
            })
            .reduce(|(mut acc_addrs, mut acc_hashes), (str_addr, str_hash)| {
                acc_addrs.push_str(&str_addr);
                acc_hashes.push_str(&str_hash);

                (acc_addrs, acc_hashes)
            })
            .unwrap_or((String::new(), String::new()));

        println!(
            "=== Migration Report ===\n\
             Seed: {}\n\
             From (Legacy IOTA) address(es):{}\n\
             To (Legacy IOTA) address(es):{}\n\
             To (Chrysalis) address: {}\n\
             Migration bundle hash(es):{}\n\
             ========================",
            seed,
            from_addr_summaries,
            bundle_addresses,
            bee_message::address::Address::Ed25519(chrysalis_addr).to_bech32("<hrp>"),
            bundle_hashes
        );
    }

    // Voilà!
    debug!("seed {}: migration finished", seed);
    Ok(())
}

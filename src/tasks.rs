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
use iota_client::api::GetAddressesBuilder;
use iota_legacy::client::builder::ClientBuilder as LegacyClientBuilder;
use iota_legacy::client::migration;
use iota_legacy::client::response::InputData;
use iota_legacy::client::AddressInput;
use iota_legacy::transaction::bundled::{Address, BundledTransaction, BundledTransactionField};
use log::*;
use rayon::prelude::*;

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
        eprintln!("> seed {}: no matching address is accepted! exiting.", seed);
        return Err(());
    }

    // This instance from an older version of iota-client connects to the legacy network.
    let mut legacy_client = LegacyClientBuilder::new()
        .node(&args.legacy_node)
        .unwrap()
        .permanode(&args.permanode)
        .unwrap()
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
    let (balance, input_data, any_spent) = match addrs_queried_results {
        Ok(info) => info,
        Err(err) => {
            error!(
                "seed {}: failed to fetch address information: {}",
                seed, err
            );
            eprintln!(
                "> seed {}: failed to fetch address information: {}",
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
        eprintln!("> seed {}: nothing can be migrated! exiting", seed);
        return Err(());
    }

    // Filter out spent addresses, if there is any.
    let mut input_data: Vec<_> = if any_spent {
        debug!("seed {}: filtering out already spent addresses", seed);

        input_data
            .into_iter()
            .filter(|data| {
                if data.spent {
                    warn!(
                        "seed {}: address {} has been spent, dropping",
                        seed,
                        migration::add_tryte_checksum(data.address.clone()).unwrap()
                    );
                }

                !data.spent
            })
            .collect()
    } else {
        input_data
    };

    // If there isn't any input data, then there's nothing we can do. Exit early.
    if input_data.is_empty() {
        warn!("seed {}: nothing can be migrated! exiting", seed);
        eprintln!("> seed {}: nothing can be migrated! exiting", seed);
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

                    if last_sum > migration::DUST_THRESHOLD {
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

            bundle_balance >= migration::DUST_THRESHOLD
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
        let generated_addrs = async_rt
            .block_on(
                GetAddressesBuilder::new(&iota_client::Seed::from_bytes(account.seed()))
                    .with_account_index(args.target_account)
                    .with_range(args.target_address..args.target_address + 1)
                    .get_all_raw(),
            )
            .unwrap();

        // Unwrap the address
        let bee_message::address::Address::Ed25519(address) = generated_addrs[0].0;

        address
    };

    // Create (prepare) migration bundles using the migration facilities in the legacy client, then
    // sign on them.
    debug!("seed {}: preparing and signing migration bundles...", seed);
    let bundles_signed: Vec<_> = bundles
        .iter()
        .map(|bundle| {
            async_rt.block_on(migration::create_migration_bundle(
                &legacy_client,
                chrysalis_addr,
                bundle.clone(),
            ))
        })
        .filter_map(|result| {
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
        })
        .zip(bundles.iter())
        .map(|(prepared_bundle, input_data)| {
            // This is an older version of [Seed]
            let ternary_seed: iota_legacy::crypto::keys::ternary::seed::Seed =
                seed.parse().unwrap();

            migration::sign_migration_bundle(ternary_seed, prepared_bundle, input_data.clone())
        })
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
    let bundles_sent = if args.dry_run {
        info!(
            "seed {}: dry-run - pretending that the bundles have been sent successfully",
            seed
        );
        eprintln!("> seed {}: dry-run finished", seed);

        None
    } else {
        let f_send = |bundle: &Vec<_>| {
            async_rt.block_on(
                legacy_client
                    .send_trytes()
                    .with_trytes(bundle.clone())
                    .with_depth(2)
                    .with_local_pow(true)
                    .with_min_weight_magnitude(args.minimum_weight_magnitude)
                    .finish(),
            )
        };

        let f_filter = |result: Result<_, _>| {
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
        };

        let bundles_sent: Vec<_> = if args.parallel_mode.is_parallel_search() {
            bundles_signed
                .par_iter()
                .map(f_send)
                .filter_map(f_filter)
                .collect()
        } else {
            bundles_signed
                .iter()
                .map(f_send)
                .filter_map(f_filter)
                .collect()
        };

        debug!("seed {}: sent {} bundles", seed, bundles_sent.len());
        eprintln!(
            "> seed {}: sent {} bundles, waiting for confirmation...",
            seed,
            bundles_sent.len()
        );

        Some(bundles_sent)
    };

    // Wait until the messages get confirmed. If not, we reattach them.
    if let Some(ref bundles_sent) = bundles_sent {
        debug!("seed {}: waiting for the confirmation of bundles...", seed);

        // Keep the starting time. If any bundle is not confirmed after 3 minutes, we perform a
        // reattachment.
        let mut time = std::time::Instant::now();

        // Tasks to run regardless of parallelism
        let f_partbndl = |txs: &&Vec<BundledTransaction>| {
            let bundle_hash = txs.first().unwrap().bundle();
            let response = async_rt.block_on(
                legacy_client
                    .find_transactions()
                    .bundles(&[*bundle_hash])
                    .send(),
            );

            match response {
                Ok(response) => {
                    let tx_hash = response.hashes[0];
                    let tx_hash_str = tx_hash
                        .encode::<iota_legacy::ternary::T3B1Buf>()
                        .iter_trytes()
                        .map(char::from)
                        .collect::<String>();
                    let response = async_rt.block_on(legacy_client.is_confirmed(&[tx_hash]));

                    match response {
                        Ok(is_confirmed) => is_confirmed[0],
                        Err(error) => {
                            warn!(
                                "seed {}: failed to query confirmation status for bundle {}: {}",
                                seed, tx_hash_str, error
                            );
                            false // treat it as unconfirmed
                        }
                    }
                }
                Err(error) => {
                    // FIXME: which bundle? We don't know the tx hash yet here!
                    warn!(
                        "seed {}: failed to query confirmation status: {}",
                        seed, error
                    );
                    false
                }
            }
        };

        // Loop until all are confirmed. XXX: what if there are some never get confirmed?
        loop {
            // Wait for 10 seconds before and during checks
            std::thread::sleep(std::time::Duration::from_secs(10));

            // We don't actually need to look at confirmed bundles any more; using partition() is
            // just for easier filtering.
            debug!("seed {}: checking for confirmation statuses...", seed);
            let (_, bundles_unconfirmed): (Vec<_>, Vec<_>) =
                if args.parallel_mode.is_parallel_search() {
                    bundles_sent.par_iter().partition(f_partbndl)
                } else {
                    bundles_sent.iter().partition(f_partbndl)
                };

            if bundles_unconfirmed.is_empty() {
                debug!("seed {}: all bundles confirmed, continue", seed);
                break;
            }

            // Otherwise, we check if it has been 3 minutes. If so, we reattch all unconfirmed
            // bundles; otherwise, just continue the loop.
            if time.elapsed().as_secs() > 180 {
                debug!("seed {}: unconfirmed bundles will be reattached", seed);

                bundles_unconfirmed
                    .iter()
                    .map(|bundle| {
                        let hash = bundle.first().unwrap().bundle();
                        let hash_str = hash
                            .encode::<iota_legacy::ternary::T3B1Buf>()
                            .iter_trytes()
                            .map(char::from)
                            .collect::<String>();

                        debug!("seed {}: reattaching bundle {}", seed, hash_str);

                        // Why we have an async fn here?
                        let builder = async_rt.block_on(legacy_client.reattach(hash));

                        async_rt.block_on(
                            builder
                                .unwrap() // XXX: what would happen here?
                                .with_depth(2)
                                .with_min_weight_magnitude(args.minimum_weight_magnitude)
                                .with_local_pow(true)
                                .finish(),
                        )
                    })
                    .for_each(|result| {
                        match result {
                            Ok(vec_tx) => {
                                let hash_str = vec_tx
                                    .first()
                                    .unwrap()
                                    .bundle()
                                    .encode::<iota_legacy::ternary::T3B1Buf>()
                                    .iter_trytes()
                                    .map(char::from)
                                    .collect::<String>();

                                debug!("seed {}: reattached bundle {}", seed, hash_str);
                            }
                            Err(err) => {
                                // XXX: which bundle?
                                warn!("seed {}: failed to reattach a bundle: {}", seed, err);
                            }
                        }
                    });

                // Update the timer
                time = std::time::Instant::now();
            }
        }
    }

    // Print a summary on this migration task.
    let from_addrs_info = input_data
        .iter()
        .map(|data| {
            format!(
                "\n- {} ({} i)",
                migration::add_tryte_checksum(data.address.clone()).unwrap(),
                data.balance
            )
        })
        .reduce(|mut acc, summary| {
            acc.push_str(&summary);
            acc
        })
        .unwrap_or_default();
    let total_amount: u64 = input_data.iter().map(|data| data.balance).sum();
    let to_addr_ternary = migration::add_tryte_checksum(
        iota_legacy::client::migration::encode_migration_address(chrysalis_addr).unwrap(),
    )
    .unwrap();
    let to_addr_bech32 = bee_message::address::Address::Ed25519(chrysalis_addr).to_bech32("iota");
    let bundles_str: String = if let Some(ref bundles_sent) = bundles_sent {
        bundles_sent
            .iter()
            .flatten()
            .map(|bundle| {
                let mut trits =
                    iota_legacy::ternary::TritBuf::<iota_legacy::ternary::T1B1Buf>::zeros(8019); // copied from wallet.rs
                bundle.as_trits_allocated(&mut trits);

                format!(
                    "\n- {}",
                    trits
                        .encode::<iota_legacy::ternary::T3B1Buf>()
                        .iter_trytes()
                        .map(char::from)
                        .collect::<String>()
                )
            })
            .collect()
    } else {
        Default::default()
    };
    let bundle_hashes: String = if let Some(ref bundles_sent) = bundles_sent {
        bundles_sent
            .iter()
            .map(|bundle| {
                format!(
                    "\n- {}",
                    bundle
                        .first()
                        .unwrap()
                        .bundle()
                        .to_inner()
                        .encode::<iota_legacy::ternary::T3B1Buf>()
                        .iter_trytes()
                        .map(char::from)
                        .collect::<String>()
                )
            })
            .reduce(|mut acc, str_hash| {
                acc.push_str(&str_hash);

                acc
            })
            .unwrap_or_default()
    } else {
        Default::default()
    };

    println!(
        "=== Migration Report ===\n\
            Seed: {}\n\
            From:{}\n\
            To:\n\
            - {} (legacy ternary address)\n\
            - {} (Chrysalis address)\n\
            Amount: {} i \n\
            Transaction bundle hash(es):{}\n\
            Bundle trytes:{}\n\
            ========================",
        seed,
        from_addrs_info,
        to_addr_ternary,
        to_addr_bech32,
        total_amount,
        bundle_hashes,
        bundles_str
    );

    Ok(())
}

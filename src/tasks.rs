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
use std::sync::{Arc, Mutex};
// use iota_legacy::client::builder::Network as LegacyNetwork;
use iota_legacy::client::AddressInput;
use iota_legacy::client::GetAddressesBuilder;
use iota_legacy::transaction::bundled::{Address, BundledTransaction, BundledTransactionField};
use iota_legacy::client::response::InputData;
use iota_legacy::client::migration;

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

fn verify_addresses(
    seed: &str,
    addrs: &Addrs,
    security_level: u8,
    parallel: bool,
) -> Result<Addrs, ()> {
    let verified_addrs = Arc::new(Mutex::new(Addrs::new()));

    // The task to run regardless of parallelism
    let task_addr_eq = |addr: &AddrInfo| {
        if let Ok(vaddr) = verify_address(seed.to_string(), addr.clone(), security_level.clone()) {
            debug!("accept matching address {}", vaddr.addr);
            verified_addrs.lock().unwrap().push(vaddr);
        } else {
            warn!("reject mismatch address {}", addr.addr);
        }
    };

    if parallel {
        addrs.par_iter().for_each(task_addr_eq);
    } else {
        addrs.iter().for_each(task_addr_eq);
    }

    if verified_addrs.lock().unwrap().len() == 0 {
        warn!("no matching address is accepted!");
        return Err(());
    }

    // Test balances and spending statuses
    debug!("connecting to the legacy IOTA network to check address information...");

    let mut legacy_client = LegacyClientBuilder::new()
        .node(&crate::LEGACY_TESTNET_NODE_URL)
        .unwrap()
        .permanode(&crate::PERMANODE_URL)
        .unwrap()
        // .network(LegacyNetwork::Devnet) // ???
        .quorum(true)
        .build()
        .unwrap();

    let prepared_addrs: Vec<AddressInput> = {
        verified_addrs
            .lock()
            .unwrap() // XXX
            .iter()
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
                    index: addr.idx.try_into().unwrap(), // XXX: usize -> u64
                    security_lvl: security_level,
                }
            })
            .collect()
    };

    let result = {
        let async_rt = tokio::runtime::Runtime::new().unwrap();
        async_rt.block_on(
            legacy_client
                .get_ledger_account_data_for_migration()
                .with_addresses(prepared_addrs)
                .finish(),
        )
    };

    let unspent_addrs = match result {
        Ok((total_balance, input_data, any_spent)) => {
            debug!(
                "total balance {}, {} input data, any spent {}",
                total_balance,
                input_data.len(),
                any_spent
            );

            let accepted_data = {
                input_data
                    .iter()
                    .zip(verified_addrs.lock().unwrap().iter())
                    .filter_map(|(input_addr, verified_addr)| {
                        debug!("comparing {}", verified_addr.addr);
                        trace!("{:?}", input_addr);

                        let is_balance_match = input_addr.balance == (verified_addr.bal as u64);
                        let is_unspent = !input_addr.spent;

                        if !is_balance_match {
                            warn!("rejecting {}: balance mismatch", verified_addr.addr);
                            return None;
                        }

                        if !is_unspent {
                            warn!("rejecting {}: spent", verified_addr.addr);
                            return None;
                        }

                        Some(verified_addr.clone())
                    })
                    .collect()
            };

            Addrs::from_inner(accepted_data)
        }
        Err(err) => {
            error!("failed to fetch address data: {}", err);
            return Err(());
        }
    };

    Ok(unspent_addrs)
}

fn sign_migration_bundles(
    _args: &Args,
    seed: &str,
    account: &ChrysalisAccount,
    security_level: u8,
    addr_bundles: &Vec<Vec<&AddrInfo>>,
) -> Result<Vec<Vec<BundledTransaction>>, ()> {
    debug!("preparing migration bundles...");

    let mut legacy_client = LegacyClientBuilder::new()
        .node(&crate::LEGACY_TESTNET_NODE_URL)
        .unwrap()
        .permanode(&crate::PERMANODE_URL)
        .unwrap()
        // .network(LegacyNetwork::Devnet) // ???
        .quorum(true)
        .build()
        .unwrap();

    let chrysalis_addr = {
        let generated_addrs = GetAddressesBuilder::new(
            &iota_legacy::client::Seed::from_bytes(account.seed()).unwrap(),
        )
        .with_account_index(0)
        .with_range(0..1)
        .finish()
        .unwrap(); // XXX

        generated_addrs.get(0).unwrap().clone()
    };
    info!("target Chrysalis address: {}", chrysalis_addr);

    let prepared_bundles: Vec<Vec<AddressInput>> = addr_bundles
        .iter()
        .map(|bundle| {
            bundle
                .iter()
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
                        index: addr.idx.try_into().unwrap(), // XXX: usize -> u64
                        security_lvl: security_level,
                    }
                })
                .collect()
        })
        .collect();

    // XXX: the following 2 steps are unfortunately needed because the input of
    // migration::create_migration_bundle() is Vec<InputData>, which comes from a query from a
    // client instance. What is done below is to fetch this data again (it might have been fetched
    // during verify_address), and filter it, in order to make our data usable with
    // migration::create_migration_bundle().

    debug!("connecting to the legacy IOTA network to check address information...");

    let results = {
        let async_rt = tokio::runtime::Runtime::new().unwrap();

        async_rt.block_on(async {
            let mut results = Vec::new();

            // XXX: this unfortunately cannot be parallelized, as a Mutex is not Send and cannot be
            // used during an await, as the lock may lock forever.
            for bundle in prepared_bundles.into_iter() {
                let data = legacy_client
                    .get_ledger_account_data_for_migration()
                    .with_addresses(bundle)
                    .finish()
                    .await;

                results.push(data);
            }

            results
        })
    };

    // Abort on any error
    {
        let mut any_error = false;

        for result in results.iter() {
            if let Err(ref e) = result {
                error!("failed to fetch address information: {}, aborting.", e);
                any_error = true;
            }
        }

        if any_error {
            return Err(());
        }
    }

    debug!("filtering data...");

    let filtered_bundles: Vec<Vec<InputData>> = results
        .into_iter()
        .zip(addr_bundles.iter())
        .filter_map(|(input_bundle, addr_bundle)| {
            if input_bundle.is_ok() {
                Some((input_bundle.unwrap(), addr_bundle))
            } else {
                None
            }
        })
        .filter(|((input_bal, input_data, _), addr_bundle)| {
            let input_bundle_balance: u64 = *input_bal;
            let addr_bundle_balance: u64 = addr_bundle
                .iter()
                .map(|bundle| bundle.bal as u64) // XXX
                .sum();

            let is_balance_match = input_bundle_balance == addr_bundle_balance;
            let is_addresses_match = input_data
                .iter()
                .zip(addr_bundle.iter())
                .fold(true, |acc, (input_bundle, addr_bundle)| {
                    // let is_addr_match = input_bundle.address == addr_bundle.addr; // FIXME
                    let is_idx_match = input_bundle.index == addr_bundle.idx as u64;
                    let is_bal_match = input_bundle.balance == addr_bundle.bal as u64;

                    acc && (is_idx_match && is_bal_match)
                });

                is_balance_match && is_addresses_match
        })
        .map(|((_, input_data, _), _)| input_data)
        .collect();

    debug!("creating and signing the bundles...");
    let created_bundles = {
        let async_rt = tokio::runtime::Runtime::new().unwrap();
        let mut bundles = Vec::new();

        for bundle in filtered_bundles.iter() {
            let created = async_rt.block_on(
                migration::create_migration_bundle(&legacy_client, chrysalis_addr, bundle.clone())
            );

            bundles.push(created.unwrap()); // XXX
        }

        bundles
    };

    let signed_bundles: Vec<Vec<BundledTransaction>> = created_bundles
        .into_iter()
        .zip(filtered_bundles.into_iter())
        .map(|(created_bundle, filtered_bundle)| {
            let ternary_seed: iota_legacy::crypto::keys::ternary::seed::Seed = seed.parse().unwrap(); // XXX
            migration::sign_migration_bundle(ternary_seed, created_bundle, filtered_bundle)
        })
        .filter_map(|result| result.ok()) // XXX
        .collect();

    info!("signed bundles: {:#?}", signed_bundles);

    Ok(signed_bundles)
}

async fn send_migration_bundle() -> Result<(), ()> {
    Ok(())
}

fn send_migration_bundles() -> Result<(), ()> {
    Ok(())
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
    let mut addrs = if args.skip_verification {
        debug!("skipping address verification");
        addrs
    } else {
        debug!("verifying addresses");

        let addr_results = verify_addresses(
            &seed,
            &addrs,
            args.security_level,
            args.parallel_mode.is_parallel_search(),
        );

        let verified_addrs = if let Ok(addrs) = addr_results {
            if addrs.len() == 0 {
                warn!("no address is verified for seed {}, nothing to do!", seed);
                return Err(());
            }

            addrs
        } else {
            error!("failed to verify addresses, exiting.");
            return Err(());
        };

        debug!("verified {} address(es)", verified_addrs.len());
        trace!("{:?}", verified_addrs);

        verified_addrs
    };

    if addrs.len() == 0 {
        warn!("no address is provided for seed {}, nothing to do!", seed);
        return Err(());
    }

    debug!("sorting addresses");
    addrs.sort_unstable_by_key(|info| info.bal);

    debug!("partitioning addresses into at-least-1-Mi bundles");
    let addr_bundles: Vec<Vec<&AddrInfo>> =
        addrs
            .iter()
            .fold(Vec::new(), |acc: Vec<Vec<&AddrInfo>>, info| {
                let mut new_acc = acc.clone();
                let last = new_acc.pop();

                if let Some(mut last) = last {
                    // Check if the last segment contains at least 1 Mi
                    let last_sum: usize = last.iter().map(|info| info.bal).sum();

                    if last_sum > 1_000_000 {
                        // Push back the last segment, create a new segment
                        let mut new = Vec::new();
                        new.push(info);
                        new_acc.push(last);
                        new_acc.push(new);
                    } else {
                        // Continue adding into the last segment
                        last.push(info);
                        new_acc.push(last);
                    }
                } else {
                    // This is the first segment, just create and put in
                    let mut new = Vec::new();
                    new.push(info);
                    new_acc.push(new);
                }

                new_acc
            });

    trace!("{:?}", addr_bundles);

    debug!("checking for dusts");
    let dust_bundles: Vec<usize> = addr_bundles
        .iter()
        .map(|bundle| bundle.iter().map(|info| info.bal).sum())
        .filter(|balance| *balance < 1_000_000)
        .collect();

    if !dust_bundles.is_empty() {
        for dust_bundle in dust_bundles {
            warn!("this bundle contains < 1 Mi balance, which is considered as a dust input, and will not be migrated: {:?}", dust_bundle);
        }
    } else {
        debug!("no dust bundle");
    }

    debug!("signing bundles");
    let _signed_bundles = sign_migration_bundles(
        &args,
        &seed,
        &account,
        args.security_level,
        &addr_bundles,
    );

    debug!("sending bundles");
    let _migrated_bundles = send_migration_bundles();

    debug!("migration finished");

    Ok(())
}

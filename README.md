# IOTA Migration CLI

This tool is designed to perform quick migrations from the legacy IOTA network to the Chrysalis IOTA network.

Two input files are required: one with seeds, and another with addresses. Specify them via the `--seeds` and `--addresses` command line arguments.

Each line in the seeds file should contain exactly one seed. For example:

```sh
# any unrecognized line will be silently ignored
GTGGKZCVUOB9WNCKDVBSUHSWF9PDQYOISURVXGXONDDOJFBAWOQLZCCMJVUFKTHEXYCXRRKCZOSXMEWZW
```

Each line in the addresses file should contain three (3) columns, separated by whitespaces: ternary address, address index, and balance. For example:

```sh
# any unrecognized line will be silently ignored
# address index balance
QKHKLYQKEIEUWFXVFVHPXAENGUHGRJJWMLVEEEEJMBKBEQWIWJSWLVBXADS9UHLDCSWZEPOPSBJIKDXJBDXVJNRJXB 7 1500000
BJGXSCHGTGHFLPVUYEMRJUQCB9JUMYTPFXBQEZYCPLRACSNPUWYGWY9ZEHWJSXOMOWJJHYCZTVHLUYXLZJGITOJCXY 9 1500000
...
```

It's fine to put multiple seeds and multiple addresses that belong to multiple seeds together, as the migration CLI will match the addresses against the seeds by generating addresses from the seeds and compare them.

A few variables can be specified from the command line. Execute:

```
./iota-migration-cli --help
```

... to view a list of configurable options. A typical invocation would be as follows:

```
./iota-migration-cli --seeds seeds.txt --addresses addresses.txt --parallel-mode=all
```

To use a different node (the default is a testnet node), use the command line option `--legacy-node`, followed by the URL to a node. For example:

```sh
./iota-migration-cli --seeds seeds.txt --addresses addresses.txt --legacy-node 'https://nodes-legacy.iotatestmigration6.net'
```

To turn on logging, the enviroment variable `RUST_LOG` needs to be specified before the invocation of migration CLI. For example:

```sh
# There are several levels of logging available: error, warning, info, debug, trace (from the most silent to the most verbose)

# Alternatively, use export to pre-define the environment variable
# export RUST_LOG='iota_migration_cli=debug'

RUST_LOG='iota_migration_cli=debug' ./iota-migration-cli --seeds seeds.txt --addresses addresses.txt --parallel-mode=all
```

The full specification of `RUST_LOG` can be found [here](https://docs.rs/env_logger/latest/env_logger/#enabling-logging).

Logs are output to `stderr`, while critical information (e.g. the generated Chrysalis account seed mnemonic, the migration summary) are printed to `stdout`. It's therefore critical to ensure that **the terminal has sufficient rollback buffer**; otherwise they'll be lost. One solution is to redirect `stdout`:

```sh
./iota-migration-cli --seeds seeds.txt --addresses addresses.txt > /tmp/summary.txt

# Then look at the file in another terminal perhaps
# tail -f /tmp/summary.txt
```

It's also possible to redirect all outputs to a log file:

```sh
RUST_LOG='iota_migration_cli=debug' ./iota-migration-cli --seeds seeds.txt --addresses addresses.txt > /tmp/summary.txt 2>&1

# Then follow the progress in another terminal perhaps
# tail -f /tmp/summary.txt
```

It's also possible to redirect `stdout` / `stderr` _while_ keeping them on the terminal:

```sh
RUST_LOG='iota_migration_cli=debug' ./iota-migration-cli --seeds seeds.txt --addresses addresses.txt > summary.txt 2>&1 | tee /tmp/summary.txt

# Remote 2>&1 to tee stdout only
```

The migration CLI does not monitor the status of transaction (i.e. it does not wait until the transaction bundles are confirmed). If anything unexpected happen, re-run the tool to try again. Relevant information is retrieved from the network in prior to migration. Alternatively, use the command line flag `--dry-run` to stop really sending the migration bundles to the network. This is convenient for checking whether the transactions to be sent are correct or not.

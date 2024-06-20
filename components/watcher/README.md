# Watcher

A watcher is component designated by the validator. Its role is to monitor the key events and the signed receipts from witnesses.

## Usage

To start witness, execute the following command:
```cargo watcher run -- -c watcher.yaml```

The `watcher.yaml` file allows customization of the following elements:

- `db_path`: specifies the path to the directory where the database will be created.
- `public_url` and `http_port`: determine the address and port on which the witness will listen.
- `seed`: seed in the [CESR format](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#name-master-code-table), that will be used for watcher keypair generation.
- `escrow_config`: specifies the time in seconds after which unconfirmed events will be automatically removed from the database.

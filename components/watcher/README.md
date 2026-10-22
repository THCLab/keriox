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

## Abandoned identifiers

Once an identifier is abandoned (a rotation with no next keys, `n=[]`,
`nt=0`), or incepted non-transferable (an inception with no next keys), the watcher serves its final key event log, stops polling
witnesses for it and answers full-log queries without waiting on them.
`GET /identifiers/{aid}/state` reports what the watcher has seen of an
identifier, including `"transferable"` and `"abandoned": {"sn", "said"}`, without authentication
(`404` for unknown ones). It answers from local data only, so it never makes
the watcher query witnesses. `GET /info` lists `"features":
["abandonment"]`.

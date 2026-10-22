# Witness

A witness is a component designated by the controller of an identifier. Its role is to verify, sign and keep events associated with identifier.

## Usage

To start witness, execute the following command:
```cargo witness run -- -c witness.yaml```

The `witness.yaml` file allows customization of the following elements:

- `db_path`: specifies the path to the directory where the database will be created.
- `public_url` and `http_port`: determine the address and port on which the witness will listen.
- `seed`: seed in the [CESR format](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#name-master-code-table), that will be used for witness keypair generation.
- `escrow_config`: specifies the time in seconds after which unconfirmed events will be automatically removed from the database.

## Abandoned identifiers

Once an identifier is abandoned (a rotation with no next keys, `n=[]`,
`nt=0`), or incepted non-transferable (an inception with no next keys), the witness refuses every later event for it with
`410 Gone`. `GET /identifiers/{aid}/state` reports any identifier it
receipts, including `"transferable"` and `"abandoned": {"sn", "said"}`, without authentication
(`404` for unknown ones), and `GET /info` lists `"features":
["abandonment"]`. Upgrade every witness of an identifier before it is
abandoned.

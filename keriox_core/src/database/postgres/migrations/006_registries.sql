-- ACDC 2.0 state registries (teliox RegistryStore): the raw bodies of
-- registry events, every distinct event at a position kept as evidence of
-- duplicity, and state blocks under their BLIDs. Blinding salts are not
-- stored: the Issuer keeps them with its other secrets.
CREATE TABLE registry_events (
    registry TEXT NOT NULL,
    sn BIGINT NOT NULL,
    said TEXT NOT NULL,
    body BYTEA NOT NULL,
    PRIMARY KEY (registry, sn, said)
);

CREATE TABLE registry_blocks (
    blid TEXT PRIMARY KEY,
    block TEXT NOT NULL
);

-- ACDC 2.0 state registries (teliox RegistryStore): the raw bodies of
-- registry events, every distinct event at a position kept as evidence of
-- duplicity; blinded state blocks under their BLIDs; and the salts of the
-- registries an Issuer runs, a secret shared only with Disclosers.
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

CREATE TABLE registry_salts (
    registry TEXT PRIMARY KEY,
    salt TEXT NOT NULL
);

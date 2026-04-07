-- ===========================================
-- KEL Tables (EventDatabase)
-- ===========================================

-- Maps (identifier, sn) -> event_digest
-- ReDB: KELS: TableDefinition<(&str, u64), &[u8]>
CREATE TABLE kels (
    identifier TEXT NOT NULL,
    sn BIGINT NOT NULL,
    digest BYTEA NOT NULL,
    PRIMARY KEY (identifier, sn)  -- UNIQUE constraint prevents duplicate sn
);
CREATE INDEX idx_kels_identifier ON kels(identifier);

-- Maps identifier -> serialized IdentifierState
-- ReDB: KEY_STATES: TableDefinition<&str, &[u8]>
CREATE TABLE key_states (
    identifier TEXT PRIMARY KEY,
    state_data BYTEA NOT NULL  -- rkyv serialized IdentifierState
);

-- Maps digest -> serialized event
-- ReDB: EVENTS: TableDefinition<&[u8], &[u8]>
CREATE TABLE events (
    digest BYTEA PRIMARY KEY,
    event_data BYTEA NOT NULL  -- rkyv serialized KeriEvent<KeyEvent>
);

-- Multimap: digest -> multiple signatures
-- ReDB: SIGS: MultimapTableDefinition<&[u8], &[u8]>
CREATE TABLE signatures (
    digest BYTEA NOT NULL,
    signature_data BYTEA NOT NULL,  -- rkyv serialized IndexedSignature
    PRIMARY KEY (digest, signature_data)  -- Prevents duplicate signatures
);

-- Multimap: digest -> multiple non-transferable receipts
-- ReDB: NONTRANS_RCTS: MultimapTableDefinition<&[u8], &[u8]>
CREATE TABLE nontrans_receipts (
    digest BYTEA NOT NULL,
    receipt_data BYTEA NOT NULL,  -- rkyv serialized Nontransferable
    PRIMARY KEY (digest, receipt_data)
);

-- Multimap: digest -> multiple transferable receipts
-- ReDB: TRANS_RCTS: MultimapTableDefinition<&[u8], &[u8]>
CREATE TABLE trans_receipts (
    digest BYTEA NOT NULL,
    receipt_data BYTEA NOT NULL,  -- rkyv serialized Transferable
    PRIMARY KEY (digest, receipt_data)
);

-- Maps digest -> seal data
-- ReDB: SEALS: TableDefinition<&[u8], &[u8]>
CREATE TABLE seals (
    digest BYTEA PRIMARY KEY,
    seal_data BYTEA NOT NULL  -- rkyv serialized SourceSeal
);

-- ===========================================
-- TEL Tables (TelEventDatabase)
-- ===========================================

-- TEL events storage: digest -> CBOR serialized VerifiableEvent
CREATE TABLE tel_events (
    digest TEXT PRIMARY KEY,
    event_data BYTEA NOT NULL
);

-- VC TEL index: (vc_identifier, sn) -> event_digest
CREATE TABLE vc_tels (
    identifier TEXT NOT NULL,
    sn BIGINT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (identifier, sn)
);
CREATE INDEX idx_vc_tels_identifier ON vc_tels(identifier);

-- Management TEL index: (registry_identifier, sn) -> event_digest
CREATE TABLE management_tels (
    identifier TEXT NOT NULL,
    sn BIGINT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (identifier, sn)
);
CREATE INDEX idx_management_tels_identifier ON management_tels(identifier);

-- ===========================================
-- TEL Escrow Tables (TelEscrowDatabase)
-- ===========================================

-- Missing KEL issuer event escrow: kel_digest -> [tel_digest]
CREATE TABLE tel_missing_issuer_escrow (
    kel_digest TEXT NOT NULL,
    tel_digest TEXT NOT NULL,
    PRIMARY KEY (kel_digest, tel_digest)
);

-- Out-of-order TEL events escrow: (identifier, sn) -> [tel_digest]
CREATE TABLE tel_out_of_order_escrow (
    identifier TEXT NOT NULL,
    sn BIGINT NOT NULL,
    tel_digest TEXT NOT NULL,
    PRIMARY KEY (identifier, sn, tel_digest)
);

-- Missing registry TEL events escrow: registry_id -> [tel_digest]
CREATE TABLE tel_missing_registry_escrow (
    registry_id TEXT NOT NULL,
    tel_digest TEXT NOT NULL,
    PRIMARY KEY (registry_id, tel_digest)
);

-- ===========================================
-- Escrow Tables
-- ===========================================

-- Unified escrow table (replaces dynamic MultimapTableDefinition per escrow type)
-- ReDB: sn_key_table: MultimapTableDefinition<(&str, u64), &[u8]>
CREATE TABLE escrow_events (
    escrow_type TEXT NOT NULL,  -- 'partially_signed', 'out_of_order', 'partially_witnessed', etc.
    identifier TEXT NOT NULL,
    sn BIGINT NOT NULL,
    digest BYTEA NOT NULL,
    PRIMARY KEY (escrow_type, identifier, sn, digest)  -- Allows multiple digests per (type, id, sn)
);
CREATE INDEX idx_escrow_lookup ON escrow_events(escrow_type, identifier, sn);

-- Escrow timestamps
-- ReDB: dts_table: TableDefinition<&[u8], u64>
CREATE TABLE escrow_timestamps (
    digest BYTEA PRIMARY KEY,
    timestamp_secs BIGINT NOT NULL  -- seconds since UNIX_EPOCH
);

-- ===========================================
-- OOBI Tables
-- ===========================================

-- Location scheme OOBIs: (eid, scheme) -> OOBI data
CREATE TABLE location_oobis (
    eid TEXT NOT NULL,
    scheme TEXT NOT NULL,
    oobi_data BYTEA NOT NULL,
    PRIMARY KEY (eid, scheme)
);

-- End role OOBIs: (cid, role) -> multiple OOBIs
CREATE TABLE end_role_oobis (
    id SERIAL PRIMARY KEY,
    cid TEXT NOT NULL,
    role TEXT NOT NULL,
    eid TEXT NOT NULL,
    oobi_data BYTEA NOT NULL
);
CREATE INDEX idx_end_role_lookup ON end_role_oobis(cid, role);


-- ===========================================
-- KSN Tables
-- ===========================================

-- Maps digest -> serialized SignedReply (KSN log)
CREATE TABLE ksns (
    digest BYTEA PRIMARY KEY,
    ksn_data BYTEA NOT NULL  -- CBOR serialized SignedReply
);

-- Maps (about_who, from_who) -> digest (accepted KSN index)
CREATE TABLE accepted_ksns (
    about_who TEXT NOT NULL,
    from_who  TEXT NOT NULL,
    digest    BYTEA NOT NULL,
    PRIMARY KEY (about_who, from_who)
);

-- The KERI 1.0 TEL (vcp/iss/rev with backers) is replaced by the ACDC 2.0
-- registries of migration 006; its events and escrows are dropped.
DROP TABLE IF EXISTS tel_events;
DROP TABLE IF EXISTS vc_tels;
DROP TABLE IF EXISTS management_tels;
DROP TABLE IF EXISTS tel_missing_issuer_escrow;
DROP TABLE IF EXISTS tel_out_of_order_escrow;
DROP TABLE IF EXISTS tel_missing_registry_escrow;

-- When each event entered its escrow, so that escrows drop events they
-- held longer than their timeout. Events escrowed before this migration
-- count from the time it ran.
ALTER TABLE escrow_events
    ADD COLUMN inserted_at BIGINT NOT NULL DEFAULT (extract(epoch FROM now())::BIGINT);

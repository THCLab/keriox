-- Every event a KEL accepted, numbered in the order it was first seen: the
-- first-seen number, fn. A KEL accepted before this migration was seen in
-- the order of its sequence numbers.
CREATE TABLE first_seen (
    identifier TEXT NOT NULL,
    fn BIGINT NOT NULL,
    digest BYTEA NOT NULL,
    PRIMARY KEY (identifier, fn)
);

INSERT INTO first_seen (identifier, fn, digest)
SELECT identifier, sn, digest FROM kels;

-- Events a superseding recovery took off a KEL, in the order they were
-- superseded. They stay in the KEL's history as its disputed branch.
CREATE TABLE disputed_events (
    identifier TEXT NOT NULL,
    ordinal BIGSERIAL NOT NULL,
    sn BIGINT NOT NULL,
    digest BYTEA NOT NULL,
    PRIMARY KEY (identifier, ordinal)
);

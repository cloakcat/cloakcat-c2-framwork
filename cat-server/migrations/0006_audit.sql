CREATE TABLE audit (
    id          BIGSERIAL   PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target_type TEXT        NOT NULL,
    target_id   TEXT        NOT NULL,
    context     JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_actor_idx      ON audit (actor);
CREATE INDEX audit_target_id_idx  ON audit (target_id);
CREATE INDEX audit_ts_idx         ON audit (ts DESC);

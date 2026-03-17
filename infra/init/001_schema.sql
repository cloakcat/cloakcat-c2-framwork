CREATE TABLE agents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id text NOT NULL UNIQUE,
    platform text NOT NULL,
    token_b64 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NULL
);

CREATE TABLE commands (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    command text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    command_id uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    exit_code integer NOT NULL,
    stdout text NOT NULL,
    stderr text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
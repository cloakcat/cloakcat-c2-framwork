ALTER TABLE agents
ADD COLUMN tags text[] NOT NULL DEFAULT '{}'::text[];
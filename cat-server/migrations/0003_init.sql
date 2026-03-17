ALTER TABLE agents
ADD COLUMN profile_name text,
ADD COLUMN beacon_min_ms integer,
ADD COLUMN beacon_max_ms integer,
ADD COLUMN backoff_max_ms integer,
ADD COLUMN kill_after_hours integer;
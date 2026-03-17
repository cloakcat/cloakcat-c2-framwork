ALTER TABLE agents
ADD COLUMN hostname text,
ADD COLUMN username text,
ADD COLUMN os_version text,
ADD COLUMN ip_addrs text;
-- Outstanding-challenge caps (RFC §17.4) and the per-challenge failure budget (RFC §13.4).
--
-- TEXT rather than a bounded VARCHAR: whatever the adapter's trust policy hands us is not
-- guaranteed to be a bare address, and a length overflow here would turn /auth/init into a 500.
-- Note this column makes the table hold caller addresses — personal data on most readings, so
-- it inherits whatever retention policy covers the rest of nap_challenges.
ALTER TABLE nap_challenges ADD COLUMN client_ip TEXT;
ALTER TABLE nap_challenges ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;

-- Not optional in practice: countOutstanding() runs on every /auth/init.
CREATE INDEX idx_nap_challenges_npub ON nap_challenges (npub) WHERE state = 'issued';
CREATE INDEX idx_nap_challenges_client_ip ON nap_challenges (client_ip) WHERE state = 'issued';

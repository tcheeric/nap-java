-- Outstanding-challenge caps (RFC §17.4) and the per-challenge failure budget (RFC §13.4).
ALTER TABLE nap_challenges ADD COLUMN client_ip VARCHAR(64);
ALTER TABLE nap_challenges ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;

-- Not optional in practice: countOutstanding() runs on every /auth/init.
CREATE INDEX idx_nap_challenges_npub ON nap_challenges (npub) WHERE state = 'issued';
CREATE INDEX idx_nap_challenges_client_ip ON nap_challenges (client_ip) WHERE state = 'issued';

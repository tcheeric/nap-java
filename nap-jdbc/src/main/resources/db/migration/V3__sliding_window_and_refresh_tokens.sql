-- Columns JdbcSessionStore already reads and writes but no migration created.
--
-- Spec 006 (sliding sessions) and RFC §14.1 (refresh tokens) both widened
-- SessionRecord, and the DDL for each lived only as a Javadoc comment on
-- JdbcSessionStore. Applying V1 and V2 alone produced a nap_sessions the store
-- could neither insert into nor map a row from.

-- Spec 006. NOT NULL DEFAULT 0 so the ALTER succeeds on a populated table; the
-- backfill below then gives existing rows the values they would have been
-- created with, treating each as last active when issued and capped at its
-- current expiry — which is what a pre-006 session effectively was.
ALTER TABLE nap_sessions ADD COLUMN IF NOT EXISTS last_activity_at   BIGINT NOT NULL DEFAULT 0;
ALTER TABLE nap_sessions ADD COLUMN IF NOT EXISTS absolute_expiry_at BIGINT NOT NULL DEFAULT 0;

UPDATE nap_sessions
   SET last_activity_at   = CASE WHEN last_activity_at   = 0 THEN issued_at  ELSE last_activity_at   END,
       absolute_expiry_at = CASE WHEN absolute_expiry_at = 0 THEN expires_at ELSE absolute_expiry_at END
 WHERE last_activity_at = 0 OR absolute_expiry_at = 0;

-- RFC §14.1. Nullable throughout: refresh is opt-in, and a session issued while
-- refreshTtlSeconds was unset legitimately holds no token.
ALTER TABLE nap_sessions ADD COLUMN IF NOT EXISTS refresh_token          TEXT;
ALTER TABLE nap_sessions ADD COLUMN IF NOT EXISTS refresh_expires_at     BIGINT;
ALTER TABLE nap_sessions ADD COLUMN IF NOT EXISTS previous_refresh_token TEXT;

-- Unique rather than a plain index: two sessions sharing a refresh token would
-- make the lookup in getByRefreshToken ambiguous, and the rotation CAS assumes
-- at most one row can match. NULLs do not collide in Postgres, so the many
-- sessions without a token are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS idx_nap_sessions_refresh_token
    ON nap_sessions (refresh_token) WHERE refresh_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_nap_sessions_prev_refresh_token
    ON nap_sessions (previous_refresh_token) WHERE previous_refresh_token IS NOT NULL;

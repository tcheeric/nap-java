package xyz.tcheeric.nap.jdbc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * PostgreSQL-backed SessionStore using plain JDBC.
 *
 * <p>Spec 006 adds two columns to {@code nap_sessions}:
 * <pre>
 *   ALTER TABLE nap_sessions ADD COLUMN last_activity_at    BIGINT NOT NULL DEFAULT 0;
 *   ALTER TABLE nap_sessions ADD COLUMN absolute_expiry_at  BIGINT NOT NULL DEFAULT 0;
 *   UPDATE nap_sessions SET last_activity_at = issued_at,
 *                           absolute_expiry_at = expires_at
 *     WHERE last_activity_at = 0 OR absolute_expiry_at = 0;
 * </pre>
 * Consumers own their schema — apply this migration before deploying a NAP
 * server that reads/writes these columns.
 */
public final class JdbcSessionStore implements SessionStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcSessionStore.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final DataSource dataSource;

    public JdbcSessionStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public SessionRecord createForChallenge(SessionRecord record) {
        String sql = """
                INSERT INTO nap_sessions (session_id, challenge_id, access_token, principal_npub,
                    principal_pubkey, roles, permissions, issued_at, last_activity_at,
                    expires_at, absolute_expiry_at, step_up_token, step_up_expires_at)
                VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (challenge_id) DO NOTHING
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.sessionId());
            ps.setString(2, record.challengeId());
            ps.setString(3, record.accessToken());
            ps.setString(4, record.principalNpub());
            ps.setString(5, record.principalPubkey());
            ps.setString(6, toJson(record.roles()));
            ps.setString(7, toJson(record.permissions()));
            ps.setLong(8, record.issuedAt());
            ps.setLong(9, record.lastActivityAt());
            ps.setLong(10, record.expiresAt());
            ps.setLong(11, record.absoluteExpiryAt());
            ps.setString(12, record.stepUpToken());
            if (record.stepUpExpiresAt() == null) {
                ps.setNull(13, java.sql.Types.BIGINT);
            } else {
                ps.setLong(13, record.stepUpExpiresAt());
            }
            int rows = ps.executeUpdate();
            if (rows == 0) {
                // Already exists — return existing
                return findByChallengeId(record.challengeId()).orElse(record);
            }
            return record;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create session", e);
        }
    }

    @Override
    public Optional<SessionRecord> getBySessionId(String sessionId) {
        return findBy("session_id", sessionId);
    }

    @Override
    public Optional<SessionRecord> getByAccessToken(String accessToken) {
        return findBy("access_token", accessToken);
    }

    @Override
    public void revokeBySessionId(String sessionId, long nowUnix) {
        String sql = "UPDATE nap_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, nowUnix);
            ps.setString(2, sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to revoke session", e);
        }
    }

    @Override
    public int revokeByPrincipal(String pubkey, long nowUnix) {
        String sql = "UPDATE nap_sessions SET revoked_at = ? WHERE principal_pubkey = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, nowUnix);
            ps.setString(2, pubkey);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to revoke sessions by principal", e);
        }
    }

    @Override
    public void touch(String sessionId, long newLastActivityAt, long newExpiresAt) {
        // The UPDATE caps new_expires_at at the stored absolute_expiry_at so the
        // store never extends a session past its absolute cap, regardless of what
        // the caller passes. Only rows with no revocation and not-yet-absolute-expired
        // are updated.
        String sql = """
                UPDATE nap_sessions
                   SET last_activity_at = ?,
                       expires_at       = LEAST(?, absolute_expiry_at)
                 WHERE session_id = ?
                   AND revoked_at IS NULL
                   AND absolute_expiry_at > ?
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, newLastActivityAt);
            ps.setLong(2, newExpiresAt);
            ps.setString(3, sessionId);
            ps.setLong(4, newLastActivityAt);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to touch session", e);
        }
    }

    private Optional<SessionRecord> findByChallengeId(String challengeId) {
        return findBy("challenge_id", challengeId);
    }

    private Optional<SessionRecord> findBy(String column, String value) {
        String sql = "SELECT * FROM nap_sessions WHERE " + column + " = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, value);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to find session", e);
        }
    }

    private SessionRecord mapRow(ResultSet rs) throws SQLException {
        long issuedAt = rs.getLong("issued_at");
        long expiresAt = rs.getLong("expires_at");
        // Back-compat: rows written before spec 006 may have 0 in the new columns.
        long lastActivityAt = rs.getLong("last_activity_at");
        if (lastActivityAt == 0) lastActivityAt = issuedAt;
        long absoluteExpiryAt = rs.getLong("absolute_expiry_at");
        if (absoluteExpiryAt == 0) absoluteExpiryAt = expiresAt;
        return new SessionRecord(
                rs.getString("session_id"),
                rs.getString("challenge_id"),
                rs.getString("access_token"),
                rs.getString("principal_npub"),
                rs.getString("principal_pubkey"),
                fromJson(rs.getString("roles")),
                fromJson(rs.getString("permissions")),
                issuedAt,
                lastActivityAt,
                expiresAt,
                absoluteExpiryAt,
                rs.getObject("revoked_at") != null ? rs.getLong("revoked_at") : null,
                rs.getString("step_up_token"),
                rs.getObject("step_up_expires_at") != null ? rs.getLong("step_up_expires_at") : null
        );
    }

    private String toJson(List<String> list) {
        try {
            return MAPPER.writeValueAsString(list);
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }

    private List<String> fromJson(String json) {
        try {
            return MAPPER.readValue(json, LIST_TYPE);
        } catch (Exception e) {
            return List.of();
        }
    }
}

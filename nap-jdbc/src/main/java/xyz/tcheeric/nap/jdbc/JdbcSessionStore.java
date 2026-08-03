package xyz.tcheeric.nap.jdbc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.RotateRefreshTokenParams;
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
 * <p>The schema this class expects is {@code V1__create_nap_tables.sql} through
 * {@code V3__sliding_window_and_refresh_tokens.sql} in {@code db/migration}. V3 carries the
 * spec 006 sliding-window columns ({@code last_activity_at}, {@code absolute_expiry_at}) and
 * the RFC §14.1 refresh columns ({@code refresh_token}, {@code refresh_expires_at},
 * {@code previous_refresh_token}); before it existed, both sets lived only in this comment,
 * and a database built from V1 and V2 alone could neither accept an insert from this store
 * nor be mapped by it.
 *
 * <p>Consumers own their schema. Apply every migration through V3 before deploying — the
 * refresh columns are needed even when {@code refreshTtlSeconds} is unset, because the
 * INSERT always lists them.
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
                    expires_at, absolute_expiry_at, step_up_token, step_up_expires_at,
                    refresh_token, refresh_expires_at)
                VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?)
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
            setNullableLong(ps, 13, record.stepUpExpiresAt());
            ps.setString(14, record.refreshToken());
            setNullableLong(ps, 15, record.refreshExpiresAt());
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

    /**
     * Deliberately no {@code revoked_at IS NULL} filter and deliberately matching the
     * previous token too: a replay on a retired token is the signal rotation exists to
     * surface, and filtering it out would make a theft look like a typo.
     */
    @Override
    public Optional<SessionRecord> getByRefreshToken(String refreshToken) {
        String sql = "SELECT * FROM nap_sessions WHERE refresh_token = ? OR previous_refresh_token = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, refreshToken);
            ps.setString(2, refreshToken);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to find session by refresh token", e);
        }
    }

    @Override
    public Optional<SessionRecord> rotateRefreshToken(String sessionId, RotateRefreshTokenParams params) {
        // `refresh_token = ?` in the WHERE clause is the compare-and-swap: two concurrent
        // refreshes off one credential race here, and exactly one updates a row.
        String sql = """
                UPDATE nap_sessions
                   SET access_token           = ?,
                       expires_at             = ?,
                       last_activity_at       = ?,
                       roles                  = ?::jsonb,
                       permissions            = ?::jsonb,
                       previous_refresh_token = refresh_token,
                       refresh_token          = ?,
                       refresh_expires_at     = ?
                 WHERE session_id = ?
                   AND refresh_token = ?
                   AND revoked_at IS NULL
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, params.accessToken());
            ps.setLong(2, params.expiresAt());
            ps.setLong(3, params.now());
            ps.setString(4, toJson(params.roles()));
            ps.setString(5, toJson(params.permissions()));
            ps.setString(6, params.refreshToken());
            ps.setLong(7, params.refreshExpiresAt());
            ps.setString(8, sessionId);
            ps.setString(9, params.expectedRefreshToken());
            if (ps.executeUpdate() == 0) {
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to rotate refresh token", e);
        }
        return getBySessionId(sessionId);
    }

    @Override
    public boolean supportsRefreshTokens() {
        return true;
    }

    private static void setNullableLong(PreparedStatement ps, int index, Long value) throws SQLException {
        if (value == null) {
            ps.setNull(index, java.sql.Types.BIGINT);
        } else {
            ps.setLong(index, value);
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
                rs.getObject("step_up_expires_at") != null ? rs.getLong("step_up_expires_at") : null,
                rs.getString("refresh_token"),
                rs.getObject("refresh_expires_at") != null ? rs.getLong("refresh_expires_at") : null,
                rs.getString("previous_refresh_token")
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

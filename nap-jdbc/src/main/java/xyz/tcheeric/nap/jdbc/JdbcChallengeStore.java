package xyz.tcheeric.nap.jdbc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.OutstandingChallengeFilter;
import xyz.tcheeric.nap.core.RecordChallengeFailureResult;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * PostgreSQL-backed ChallengeStore using plain JDBC.
 */
public final class JdbcChallengeStore implements ChallengeStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcChallengeStore.class);
    private final DataSource dataSource;

    public JdbcChallengeStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void create(ChallengeRecord record) {
        String sql = """
                INSERT INTO nap_challenges (challenge_id, challenge, npub, pubkey, auth_url, auth_method,
                    state, issued_at, expires_at, client_ip, failure_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.challengeId());
            ps.setString(2, record.challenge());
            ps.setString(3, record.npub());
            ps.setString(4, record.pubkey());
            ps.setString(5, record.authUrl());
            ps.setString(6, record.authMethod());
            ps.setString(7, record.state().toWireValue());
            ps.setLong(8, record.issuedAt());
            ps.setLong(9, record.expiresAt());
            ps.setString(10, record.clientIp());
            ps.setInt(11, record.failureCount());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create challenge", e);
        }
    }

    @Override
    public Optional<ChallengeRecord> get(String challengeId) {
        String sql = "SELECT * FROM nap_challenges WHERE challenge_id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, challengeId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get challenge", e);
        }
    }

    @Override
    public RedeemResult redeem(String challengeId, RedeemParams params) {
        String sql = """
                UPDATE nap_challenges
                SET state = 'redeemed', redeemed_event_id = ?, redeemed_session_id = ?, result_cache_until = ?
                WHERE challenge_id = ? AND state = 'issued' AND expires_at > ?
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, params.eventId());
            ps.setString(2, params.sessionId());
            ps.setLong(3, params.resultCacheUntil());
            ps.setString(4, challengeId);
            ps.setLong(5, params.now());
            int updated = ps.executeUpdate();
            if (updated == 1) {
                return RedeemResult.REDEEMED;
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to redeem challenge", e);
        }

        // Check why it wasn't updated
        return get(challengeId).map(record -> {
            if (record.state() == ChallengeState.EXPIRED || record.expiresAt() < params.now()) {
                return RedeemResult.EXPIRED;
            }
            return RedeemResult.ALREADY_REDEEMED;
        }).orElse(RedeemResult.NOT_FOUND);
    }

    @Override
    public int markExpired(long nowUnix) {
        String sql = "UPDATE nap_challenges SET state = 'expired' WHERE state = 'issued' AND expires_at < ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, nowUnix);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to mark expired challenges", e);
        }
    }

    @Override
    public OptionalInt countOutstanding(OutstandingChallengeFilter filter) {
        String sql = """
                SELECT COUNT(*) AS count
                FROM nap_challenges
                WHERE state = 'issued'
                  AND expires_at >= ?
                  AND (?::text IS NULL OR npub = ?)
                  AND (?::text IS NULL OR client_ip = ?)
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, filter.now());
            ps.setString(2, filter.npub());
            ps.setString(3, filter.npub());
            ps.setString(4, filter.clientIp());
            ps.setString(5, filter.clientIp());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? OptionalInt.of(rs.getInt("count")) : OptionalInt.of(0);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to count outstanding challenges", e);
        }
    }

    /**
     * Increments and flips to {@code failed_terminal} in one statement so concurrent attempts
     * on the same challenge cannot lose increments to a read-modify-write race and slip past
     * the cap.
     */
    @Override
    public RecordChallengeFailureResult recordFailure(String challengeId, long now, int maxFailures) {
        String sql = """
                UPDATE nap_challenges
                SET failure_count = COALESCE(failure_count, 0) + 1,
                    state = CASE
                      WHEN COALESCE(failure_count, 0) + 1 >= ? THEN 'failed_terminal'
                      ELSE state
                    END
                WHERE challenge_id = ? AND state = 'issued'
                RETURNING failure_count, state
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, maxFailures);
            ps.setString(2, challengeId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return new RecordChallengeFailureResult(
                        rs.getInt("failure_count"),
                        ChallengeState.fromWireValue(rs.getString("state")));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to record challenge failure", e);
        }
    }

    private ChallengeRecord mapRow(ResultSet rs) throws SQLException {
        return new ChallengeRecord(
                rs.getString("challenge_id"),
                rs.getString("challenge"),
                rs.getString("npub"),
                rs.getString("pubkey"),
                rs.getString("auth_url"),
                rs.getString("auth_method"),
                rs.getLong("issued_at"),
                rs.getLong("expires_at"),
                ChallengeState.fromWireValue(rs.getString("state")),
                rs.getString("redeemed_event_id"),
                rs.getString("redeemed_session_id"),
                rs.getObject("result_cache_until") != null ? rs.getLong("result_cache_until") : null,
                rs.getString("client_ip"),
                rs.getInt("failure_count")
        );
    }
}


package com.pritamx.thunderantialt;

import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.logging.Level;

public final class AccountListener implements Listener {

    private final ThunderAntiAlt plugin;

    public AccountListener(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerLogin(PlayerLoginEvent event) {

        String uuid = event.getPlayer().getUniqueId().toString();
        String username = event.getPlayer().getName();

        InetAddress address = event.getAddress();
        String ip = address == null ? "UNKNOWN" : address.getHostAddress();

        synchronized (plugin.getDatabaseLock()) {

            Connection db = plugin.getDatabaseConnection();

            if (db == null) {
                deny(event, "database-error");
                return;
            }

            try {

                if (isBanned(db, uuid)) {
                    deny(event, "account-banned");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED", "Account UUID is banned.");
                    return;
                }

                boolean isMain = isMainAccount(db, uuid);
                String ownerUuid = getAuthorizedOwner(db, uuid);

                if (isMain && ownerUuid != null) {
                    deny(event, "database-error");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED",
                            "Conflicting Main and Alt records.");
                    return;
                }

                if (isMain) {
                    updateMainLastSeen(db, uuid, username);
                    audit(uuid, username, ip,
                            "MAIN_LOGIN", "Registered Main account.");
                    return;
                }

                if (ownerUuid != null) {

                    if (!isMainAccount(db, ownerUuid)) {
                        deny(event, "database-error");
                        audit(uuid, username, ip,
                                "LOGIN_BLOCKED",
                                "Alt owner does not exist.");
                        return;
                    }

                    if (isBanned(db, ownerUuid)) {
                        deny(event, "account-banned");
                        audit(uuid, username, ip,
                                "LOGIN_BLOCKED",
                                "Linked Main account is banned: " + ownerUuid);
                        return;
                    }

                    updateAltLastSeen(db, uuid, username);
                    audit(uuid, username, ip,
                            "AUTHORIZED_ALT_LOGIN",
                            "Authorized Alt. Main UUID: " + ownerUuid);
                    return;
                }

                String pendingStatus = getPendingStatus(db, uuid);

                if ("DENIED".equalsIgnoreCase(pendingStatus)) {
                    deny(event, "account-denied-login");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED",
                            "Account approval was denied.");
                    return;
                }

                recordPendingAccount(db, uuid, username, ip);

                audit(uuid, username, ip,
                        "ALT_PENDING",
                        "Unknown UUID stored for admin review.");

                deny(event, "approval-required");

            } catch (SQLException exception) {

                plugin.getLogger().log(
                        Level.SEVERE,
                        "Account verification failed for " + username,
                        exception
                );

                deny(event, "database-error");
            }
        }
    }

    private boolean isBanned(Connection db, String uuid)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1 FROM account_bans
                WHERE player_uuid = ? LIMIT 1
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isMainAccount(Connection db, String uuid)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1 FROM main_accounts
                WHERE main_uuid = ? LIMIT 1
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private String getAuthorizedOwner(Connection db, String altUuid)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT owner_uuid FROM authorized_accounts
                WHERE authorized_uuid = ? LIMIT 1
                """)) {

            ps.setString(1, altUuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("owner_uuid") : null;
            }
        }
    }

    private String getPendingStatus(Connection db, String uuid)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT status FROM pending_alt_accounts
                WHERE uuid = ? LIMIT 1
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("status") : null;
            }
        }
    }

    private void recordPendingAccount(
            Connection db,
            String uuid,
            String username,
            String ip
    ) throws SQLException {

        String now = Instant.now().toString();

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, 0, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    last_seen = excluded.last_seen
                """)) {

            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, now);
            ps.setString(5, now);
            ps.executeUpdate();
        }

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO pending_alt_accounts
                    (uuid, username, ip_address, main_uuid,
                     first_seen, last_seen, attempts, status)
                VALUES (?, ?, ?, 'UNKNOWN', ?, ?, 1, 'PENDING')
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    last_seen = excluded.last_seen,
                    attempts = pending_alt_accounts.attempts + 1,
                    status = CASE
                        WHEN pending_alt_accounts.status = 'DENIED'
                        THEN 'DENIED'
                        ELSE 'PENDING'
                    END
                """)) {

            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, now);
            ps.setString(5, now);
            ps.executeUpdate();
        }
    }

    private void updateMainLastSeen(
            Connection db,
            String uuid,
            String username
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE main_accounts
                SET username = ?, last_seen = ?
                WHERE main_uuid = ?
                """)) {

            ps.setString(1, username);
            ps.setString(2, Instant.now().toString());
            ps.setString(3, uuid);
            ps.executeUpdate();
        }
    }

    private void updateAltLastSeen(
            Connection db,
            String uuid,
            String username
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE accounts
                SET username = ?, last_seen = ?
                WHERE uuid = ?
                """)) {

            ps.setString(1, username);
            ps.setString(2, Instant.now().toString());
            ps.setString(3, uuid);
            ps.executeUpdate();
        }
    }

    private void deny(PlayerLoginEvent event, String key) {
        event.disallow(
                PlayerLoginEvent.Result.KICK_OTHER,
                plugin.getMessage(key)
        );
    }

    private void audit(
            String uuid,
            String username,
            String ip,
            String action,
            String details
    ) {
        plugin.logAudit(uuid, username, ip, action, details);
    }
}

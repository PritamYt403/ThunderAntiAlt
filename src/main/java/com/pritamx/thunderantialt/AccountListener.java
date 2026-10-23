package com.pritamx.thunderantialt;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
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

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        Player player = event.getPlayer();

        String uuid = player.getUniqueId().toString();
        String username = player.getName();

        InetAddress address = event.getAddress();
        String ip = address == null ? null : address.getHostAddress();

        if (ip == null || ip.isBlank()) {
            deny(event, "database-error");
            return;
        }

        if (player.isOp()
                || player.hasPermission("thunderantialt.bypass")) {
            return;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection connection = plugin.getDatabaseConnection();

            if (connection == null) {
                handleDatabaseFailure(event);
                return;
            }

            boolean previousAutoCommit = true;

            try {
                previousAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);

                if (isBanned(connection, uuid)) {
                    connection.rollback();
                    connection.setAutoCommit(previousAutoCommit);

                    deny(event, "account-banned");
                    audit(uuid, username, ip, "LOGIN_BLOCKED",
                            "Account is banned");
                    return;
                }

                AccountRecord account = getAccount(connection, uuid);
                PendingRecord pending = getPending(connection, uuid);

                // Main accounts are allowed to reconnect from a new IP.
                if (isMainUuid(connection, uuid)) {
                    ensureAccount(connection, uuid, username, ip, true);
                    saveMainAccount(connection, ip, uuid, username);
                    updatePendingStatus(connection, uuid, "APPROVED");

                    connection.commit();
                    connection.setAutoCommit(previousAutoCommit);

                    audit(uuid, username, ip, "MAIN_LOGIN",
                            "Main account login");
                    return;
                }

                // Previously approved accounts must still have an
                // explicit authorization relationship.
                if (isApprovedAlt(connection, uuid)) {
                    registerAuthorizedAccount(
                            connection, uuid, username, ip);

                    updatePendingStatus(connection, uuid, "APPROVED");

                    connection.commit();
                    connection.setAutoCommit(previousAutoCommit);

                    audit(uuid, username, ip, "AUTHORIZED_LOGIN",
                            "Approved alt account login");
                    return;
                }

                // Pending or denied accounts must not bypass review.
                if (pending != null) {
                    updatePendingAttempt(
                            connection, uuid, username, ip);

                    connection.commit();
                    connection.setAutoCommit(previousAutoCommit);

                    deny(event, "approval-required");

                    audit(uuid, username, ip, "LOGIN_BLOCKED",
                            "Alt account status: " + pending.status);

                    alertAdmins(username,
                            "Alt account requires approval");
                    return;
                }

                // A legacy record alone is not enough to authorize
                // an account. The authorization relationship is required.
                if (account != null
                        && isAuthorizedAlt(connection, uuid)) {
                    registerAuthorizedAccount(
                            connection, uuid, username, ip);

                    connection.commit();
                    connection.setAutoCommit(previousAutoCommit);

                    audit(uuid, username, ip, "AUTHORIZED_LOGIN",
                            "Existing authorized account");
                    return;
                }

                String mainUuid = findMainUuid(connection, ip, uuid);

                if (mainUuid == null && account != null) {
                    mainUuid = findMainForAccount(connection, uuid);
                }

                // First account seen from an IP becomes its main account.
                if (mainUuid == null && account == null) {
                    insertAccount(connection, uuid, username, ip, true);
                    saveMainAccount(connection, ip, uuid, username);

                    connection.commit();
                    connection.setAutoCommit(previousAutoCommit);

                    audit(uuid, username, ip,
                            "MAIN_ACCOUNT_REGISTERED",
                            "First account registered for IP");
                    return;
                }

                if (mainUuid == null
                        || mainUuid.isBlank()
                        || "UNKNOWN".equalsIgnoreCase(mainUuid)) {
                    mainUuid = "UNKNOWN";
                }

                if (account == null) {
                    insertAccount(connection, uuid, username, ip, false);
                } else {
                    updateBinding(connection, uuid, username, ip, false);
                }

                upsertPending(
                        connection, uuid, username, ip, mainUuid);

                connection.commit();
                connection.setAutoCommit(previousAutoCommit);

                deny(event, "approval-required");

                audit(uuid, username, ip, "ALT_PENDING",
                        "Waiting for admin approval; main UUID: "
                                + mainUuid);

                alertAdmins(username,
                        "New alt account pending approval");

            } catch (SQLException exception) {
                try {
                    connection.rollback();
                    connection.setAutoCommit(previousAutoCommit);
                } catch (SQLException rollbackException) {
                    exception.addSuppressed(rollbackException);
                }

                plugin.getLogger().log(
                        Level.SEVERE,
                        "Account verification failed for " + username,
                        exception);

                handleDatabaseFailure(event);
            }
        }
    }

    private boolean isBanned(Connection connection, String uuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM account_bans WHERE player_uuid = ? LIMIT 1")) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private boolean isMainUuid(Connection connection, String uuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM ip_main_accounts
                WHERE main_uuid = ?
                LIMIT 1
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private boolean isApprovedAlt(Connection connection, String uuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM authorized_accounts
                WHERE authorized_uuid = ?
                LIMIT 1
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private boolean isAuthorizedAlt(Connection connection, String uuid)
            throws SQLException {
        return isApprovedAlt(connection, uuid);
    }

    private String findMainUuid(
            Connection connection, String ip, String excludedUuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT main_uuid
                FROM ip_main_accounts
                WHERE ip_address = ?
                ORDER BY created_at ASC
                LIMIT 1
                """)) {
            statement.setString(1, ip);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    String mainUuid = result.getString("main_uuid");

                    if (mainUuid != null
                            && !mainUuid.equals(excludedUuid)) {
                        return mainUuid;
                    }
                }
            }
        }

        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT uuid
                FROM accounts
                WHERE ip_address = ?
                  AND approved = 1
                ORDER BY created_at ASC
                LIMIT 1
                """)) {
            statement.setString(1, ip);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    String mainUuid = result.getString("uuid");

                    if (mainUuid != null
                            && !mainUuid.equals(excludedUuid)) {
                        return mainUuid;
                    }
                }
            }
        }

        return null;
    }

    private String findMainForAccount(
            Connection connection, String uuid) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT main_uuid
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return result.getString("main_uuid");
                }
            }
        }

        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT owner_uuid
                FROM authorized_accounts
                WHERE authorized_uuid = ?
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return result.getString("owner_uuid");
                }
            }
        }

        return null;
    }

    private AccountRecord getAccount(
            Connection connection, String uuid) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT ip_address, approved
                FROM accounts
                WHERE uuid = ?
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return new AccountRecord(
                            result.getString("ip_address"),
                            result.getInt("approved"));
                }
            }
        }

        return null;
    }

    private PendingRecord getPending(
            Connection connection, String uuid) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT status
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return new PendingRecord(result.getString("status"));
                }
            }
        }

        return null;
    }

    private void saveMainAccount(
            Connection connection, String ip, String uuid, String username)
            throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ip_main_accounts
                    (ip_address, main_uuid, username, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    main_uuid = excluded.main_uuid,
                    username = excluded.username
                """)) {
            statement.setString(1, ip);
            statement.setString(2, uuid);
            statement.setString(3, username);
            statement.setString(4, now);
            statement.executeUpdate();
        }
    }

    private void upsertPending(
            Connection connection, String uuid, String username,
            String ip, String mainUuid) throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO pending_alt_accounts
                    (uuid, username, ip_address, main_uuid,
                     first_seen, last_seen, attempts, status)
                VALUES (?, ?, ?, ?, ?, ?, 1, 'PENDING')
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    main_uuid = excluded.main_uuid,
                    last_seen = excluded.last_seen,
                    attempts = pending_alt_accounts.attempts + 1
                WHERE pending_alt_accounts.status NOT IN
                    ('APPROVED', 'DENIED')
                """)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setString(4, mainUuid);
            statement.setString(5, now);
            statement.setString(6, now);
            statement.executeUpdate();
        }
    }

    private void updatePendingAttempt(
            Connection connection, String uuid, String username, String ip)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE pending_alt_accounts
                SET username = ?, ip_address = ?, last_seen = ?,
                    attempts = attempts + 1
                WHERE uuid = ?
                """)) {
            statement.setString(1, username);
            statement.setString(2, ip);
            statement.setString(3, Instant.now().toString());
            statement.setString(4, uuid);
            statement.executeUpdate();
        }
    }

    private void updatePendingStatus(
            Connection connection, String uuid, String status)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE pending_alt_accounts
                SET status = ?
                WHERE uuid = ?
                """)) {
            statement.setString(1, status);
            statement.setString(2, uuid);
            statement.executeUpdate();
        }
    }

    private void ensureAccount(
            Connection connection, String uuid, String username,
            String ip, boolean approved) throws SQLException {
        AccountRecord account = getAccount(connection, uuid);

        if (account == null) {
            insertAccount(connection, uuid, username, ip, approved);
        } else {
            updateBinding(connection, uuid, username, ip, approved);
        }
    }

    private void registerAuthorizedAccount(
            Connection connection, String uuid, String username, String ip)
            throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, 1, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    approved = 1,
                    last_seen = excluded.last_seen
                """)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setString(4, now);
            statement.setString(5, now);
            statement.executeUpdate();
        }
    }

    private void insertAccount(
            Connection connection, String uuid, String username,
            String ip, boolean approved) throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setInt(4, approved ? 1 : 0);
            statement.setString(5, now);
            statement.setString(6, now);
            statement.executeUpdate();
        }
    }

    private void updateBinding(
            Connection connection, String uuid, String username,
            String ip, boolean approved) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE accounts
                SET username = ?, ip_address = ?, approved = ?, last_seen = ?
                WHERE uuid = ?
                """)) {
            statement.setString(1, username);
            statement.setString(2, ip);
            statement.setInt(3, approved ? 1 : 0);
            statement.setString(4, Instant.now().toString());
            statement.setString(5, uuid);
            statement.executeUpdate();
        }
    }

    private void audit(
            String uuid, String username, String ip,
            String action, String details) {
        boolean blocked = action.contains("BLOCKED")
                || action.equals("ALT_PENDING");

        if (blocked && plugin.getConfig().getBoolean(
                "settings.log-blocked-attempts", true)) {
            plugin.logAudit(uuid, username, ip, action, details);
        } else if (!blocked && plugin.getConfig().getBoolean(
                "settings.log-successful-logins", true)) {
            plugin.logAudit(uuid, username, ip, action, details);
        }
    }

    private void deny(PlayerLoginEvent event, String messageKey) {
        event.disallow(
                PlayerLoginEvent.Result.KICK_OTHER,
                plugin.getMessage(messageKey));
    }

    private void handleDatabaseFailure(PlayerLoginEvent event) {
        if (plugin.getConfig().getBoolean(
                "security.fail-closed-on-database-error", true)) {
            deny(event, "database-error");
        } else {
            plugin.getLogger().warning(
                    "Database error; login allowed because fail-closed is disabled.");
        }
    }

    private void alertAdmins(String username, String reason) {
        if (!plugin.getConfig().getBoolean(
                "settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.isOp()
                        || admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(
                            plugin.getMessage("admin-blocked-login")
                                    .replace("{player}", username)
                                    .replace("{reason}", reason));
                }
            }
        });
    }

    private static final class AccountRecord {
        private final String ipAddress;
        private final int approved;

        private AccountRecord(String ipAddress, int approved) {
            this.ipAddress = ipAddress;
            this.approved = approved;
        }
    }

    private static final class PendingRecord {
        private final String status;

        private PendingRecord(String status) {
            this.status = status == null ? "PENDING" : status;
        }
    }
}

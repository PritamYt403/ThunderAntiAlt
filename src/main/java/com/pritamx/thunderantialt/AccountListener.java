
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
import java.util.UUID;
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

        if (player.hasPermission("thunderantialt.bypass")) {
            return;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection connection = plugin.getDatabaseConnection();

            if (connection == null) {
                handleDatabaseFailure(event);
                return;
            }

            try {
                connection.setAutoCommit(false);

                if (isBanned(connection, uuid)) {
                    connection.rollback();
                    connection.setAutoCommit(true);
                    deny(event, "account-banned");
                    audit(uuid, username, ip, "LOGIN_BLOCKED",
                            "Account is banned");
                    alertAdmins(username, "Account is banned");
                    return;
                }

                AccountRecord account = getAccount(connection, uuid);

                // Existing account: preserve its binding and approval.
                if (account != null) {
                    if (account.ipAddress != null
                            && !account.ipAddress.equals(ip)) {
                        connection.rollback();
                        connection.setAutoCommit(true);
                        deny(event, "ip-mismatch");
                        audit(uuid, username, ip, "LOGIN_BLOCKED",
                                "IP address mismatch");
                        alertAdmins(username, "IP address mismatch");
                        return;
                    }

                    if (account.ipAddress == null) {
                        if (plugin.getConfig().getBoolean(
                                "settings.require-new-ip-approval", true)) {
                            updateBinding(connection, uuid, username, ip, false);
                            connection.commit();
                            connection.setAutoCommit(true);

                            deny(event, "approval-required");
                            audit(uuid, username, ip, "APPROVAL_REQUIRED",
                                    "IP binding reset; approval required");
                            alertAdmins(username,
                                    "New IP binding requires approval");
                            return;
                        }

                        updateBinding(connection, uuid, username, ip, true);
                        account = getAccount(connection, uuid);
                    }

                    if (account != null && account.approved != 1) {
                        upsertPending(connection, uuid, username, ip,
                                findMainUuid(connection, ip, uuid));

                        connection.commit();
                        connection.setAutoCommit(true);

                        deny(event, "approval-required");
                        audit(uuid, username, ip, "LOGIN_BLOCKED",
                                "Account approval pending");
                        alertAdmins(username, "Account approval pending");
                        return;
                    }

                    updateLastSeen(connection, uuid, username);
                    connection.commit();
                    connection.setAutoCommit(true);

                    if (plugin.getConfig().getBoolean(
                            "settings.log-successful-logins", true)) {
                        audit(uuid, username, ip, "LOGIN_SUCCESS",
                                "Existing account login");
                    }
                    return;
                }

                // Explicitly authorized extra account.
                if (isAuthorizedAccount(connection, uuid, ip)) {
                    registerAuthorizedAccount(connection, uuid, username, ip);
                    connection.commit();
                    connection.setAutoCommit(true);
                    audit(uuid, username, ip, "AUTHORIZED_LOGIN",
                            "Authorized extra account login");
                    return;
                }

                // A known main account for this IP always has priority.
                String mainUuid = findMainUuid(connection, ip, null);

                if (mainUuid == null) {
                    // First account seen from this IP becomes the main account.
                    insertAccount(connection, uuid, username, ip, true);
                    saveMainAccount(connection, ip, uuid, username);

                    connection.commit();
                    connection.setAutoCommit(true);

                    if (plugin.getConfig().getBoolean(
                            "settings.log-successful-logins", true)) {
                        audit(uuid, username, ip, "MAIN_ACCOUNT_REGISTERED",
                                "First account registered for IP");
                    }
                    return;
                }

                // A different UUID from the same IP requires admin approval.
                insertAccount(connection, uuid, username, ip, false);
                upsertPending(connection, uuid, username, ip, mainUuid);

                connection.commit();
                connection.setAutoCommit(true);

                deny(event, "approval-required");
                audit(uuid, username, ip, "ALT_PENDING",
                        "Waiting for admin approval; main UUID: " + mainUuid);
                alertAdmins(username, "New alt account pending approval");
            } catch (SQLException exception) {
                try {
                    connection.rollback();
                    connection.setAutoCommit(true);
                } catch (SQLException rollbackException) {
                    exception.addSuppressed(rollbackException);
                }

                plugin.getLogger().log(Level.SEVERE,
                        "Account verification failed for " + username,
                        exception);
                handleDatabaseFailure(event);
            }
        }
    }

    private boolean isBanned(Connection connection, String uuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM account_bans WHERE player_uuid = ?")) {
            statement.setString(1, uuid);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private boolean isAuthorizedAccount(
            Connection connection, String uuid, String ip)
            throws SQLException {
        String sql = """
                SELECT 1
                FROM authorized_accounts a
                JOIN accounts owner ON owner.uuid = a.owner_uuid
                WHERE a.authorized_uuid = ?
                  AND owner.ip_address = ?
                  AND owner.approved = 1
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);
            statement.setString(2, ip);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private void registerAuthorizedAccount(
            Connection connection, String uuid, String username, String ip)
            throws SQLException {
        String now = Instant.now().toString();
        String sql = """
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, 1, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    approved = 1,
                    last_seen = excluded.last_seen
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setString(4, now);
            statement.setString(5, now);
            statement.executeUpdate();
        }
    }

    private AccountRecord getAccount(Connection connection, String uuid)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT ip_address, approved FROM accounts WHERE uuid = ?")) {
            statement.setString(1, uuid);
            try (ResultSet result = statement.executeQuery()) {
                return result.next()
                        ? new AccountRecord(
                                result.getString("ip_address"),
                                result.getInt("approved"))
                        : null;
            }
        }
    }

    private String findMainUuid(
            Connection connection, String ip, String excludedUuid)
            throws SQLException {
        String sql = """
                SELECT main_uuid
                FROM ip_main_accounts
                WHERE ip_address = ?
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, ip);
            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    String mainUuid = result.getString("main_uuid");
                    if (excludedUuid == null || !excludedUuid.equals(mainUuid)) {
                        return mainUuid;
                    }
                }
            }
        }

        // Compatibility fallback for databases created by older versions.
        String fallback = """
                SELECT uuid FROM accounts
                WHERE ip_address = ? AND approved = 1
                ORDER BY created_at ASC LIMIT 1
                """;

        try (PreparedStatement statement = connection.prepareStatement(fallback)) {
            statement.setString(1, ip);
            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    String mainUuid = result.getString(1);
                    if (excludedUuid == null || !excludedUuid.equals(mainUuid)) {
                        return mainUuid;
                    }
                }
            }
        }
        return null;
    }

    private void saveMainAccount(
            Connection connection, String ip, String uuid, String username)
            throws SQLException {
        String sql = """
                INSERT OR IGNORE INTO ip_main_accounts
                    (ip_address, main_uuid, username, created_at)
                VALUES (?, ?, ?, ?)
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, ip);
            statement.setString(2, uuid);
            statement.setString(3, username);
            statement.setString(4, Instant.now().toString());
            statement.executeUpdate();
        }
    }

    private void upsertPending(
            Connection connection,
            String uuid,
            String username,
            String ip,
            String mainUuid) throws SQLException {
        if (mainUuid == null || mainUuid.isBlank()) {
            mainUuid = "UNKNOWN";
        }

        String now = Instant.now().toString();
        String sql = """
                INSERT INTO pending_alt_accounts
                    (uuid, username, ip_address, main_uuid,
                     first_seen, last_seen, attempts, status)
                VALUES (?, ?, ?, ?, ?, ?, 1, 'PENDING')
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    last_seen = excluded.last_seen,
                    attempts = pending_alt_accounts.attempts + 1
                WHERE pending_alt_accounts.status = 'PENDING'
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setString(4, mainUuid);
            statement.setString(5, now);
            statement.setString(6, now);
            statement.executeUpdate();
        }
    }

    private void insertAccount(
            Connection connection, String uuid, String username,
            String ip, boolean approved) throws SQLException {
        String now = Instant.now().toString();
        String sql = """
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
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
        String sql = """
                UPDATE accounts
                SET username = ?, ip_address = ?, approved = ?, last_seen = ?
                WHERE uuid = ?
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            statement.setString(2, ip);
            statement.setInt(3, approved ? 1 : 0);
            statement.setString(4, Instant.now().toString());
            statement.setString(5, uuid);
            statement.executeUpdate();
        }
    }

    private void updateLastSeen(
            Connection connection, String uuid, String username)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE accounts SET username = ?, last_seen = ? WHERE uuid = ?
                """)) {
            statement.setString(1, username);
            statement.setString(2, Instant.now().toString());
            statement.setString(3, uuid);
            statement.executeUpdate();
        }
    }

    private void audit(
            String uuid, String username, String ip,
            String action, String details) {
        if (plugin.getConfig().getBoolean(
                "settings.log-blocked-attempts", true)
                || action.endsWith("_SUCCESS")
                || action.equals("MAIN_ACCOUNT_REGISTERED")) {
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
        if (!plugin.getConfig().getBoolean("settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.isOp()
                        || admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(plugin.getMessage(
                            "admin-blocked-login")
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
}

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
        UUID uuid = player.getUniqueId();
        String playerUuid = uuid.toString();
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

                if (isBanned(connection, playerUuid)) {
                    connection.rollback();
                    connection.setAutoCommit(true);
                    deny(event, "account-banned");
                    audit(playerUuid, username, ip, "LOGIN_BLOCKED", "Account is banned");
                    alertAdmins(username, "Account is banned");
                    return;
                }

                if (isAuthorizedAccount(connection, playerUuid, ip)) {
                    registerAuthorizedAccount(
                            connection, playerUuid, username, ip
                    );

                    connection.commit();
                    connection.setAutoCommit(true);

                    audit(playerUuid, username, ip,
                            "AUTHORIZED_LOGIN", "Authorized extra account login");
                    return;
                }

                AccountRecord account = getAccount(connection, playerUuid);

                if (account != null) {
                    if (account.ipAddress != null
                            && !account.ipAddress.equals(ip)) {
                        connection.rollback();
                        connection.setAutoCommit(true);

                        deny(event, "ip-mismatch");
                        audit(playerUuid, username, ip,
                                "LOGIN_BLOCKED", "IP address mismatch");
                        alertAdmins(username, "IP address mismatch");
                        return;
                    }

                    if (account.ipAddress == null) {
                        if (plugin.getConfig().getBoolean(
                                "settings.require-new-ip-approval", true)) {
                            updateBinding(connection, playerUuid, username, ip, false);

                            connection.commit();
                            connection.setAutoCommit(true);

                            deny(event, "approval-required");
                            audit(playerUuid, username, ip,
                                    "APPROVAL_REQUIRED", "IP binding reset; approval required");
                            alertAdmins(username, "New IP binding requires approval");
                            return;
                        }

                        updateBinding(connection, playerUuid, username, ip, true);
                        account = getAccount(connection, playerUuid);
                    }

                    if (account != null && account.approved != 1) {
                        connection.rollback();
                        connection.setAutoCommit(true);

                        deny(event, "approval-required");
                        audit(playerUuid, username, ip,
                                "LOGIN_BLOCKED", "Account approval pending");
                        return;
                    }

                    updateLastSeen(connection, playerUuid, username);

                    connection.commit();
                    connection.setAutoCommit(true);

                    if (plugin.getConfig().getBoolean(
                            "settings.log-successful-logins", true)) {
                        audit(playerUuid, username, ip,
                                "LOGIN_SUCCESS", "Existing account login");
                    }
                    return;
                }

                int configuredLimit = Math.max(1,
                        plugin.getConfig().getInt(
                                "settings.max-accounts-per-ip", 1));

                int effectiveLimit = getIpLimit(connection, ip, configuredLimit);
                int accountCount = countApprovedAccounts(connection, ip);

                if (accountCount >= effectiveLimit) {
                    insertAccount(connection, playerUuid, username, ip, false);

                    connection.commit();
                    connection.setAutoCommit(true);

                    deny(event, "account-limit");
                    audit(playerUuid, username, ip,
                            "ACCOUNT_LIMIT_BLOCKED",
                            "IP account limit reached: " + effectiveLimit);
                    alertAdmins(username, "IP account limit reached");
                    return;
                }

                boolean approvalRequired = plugin.getConfig().getBoolean(
                        "settings.require-new-ip-approval", true);

                insertAccount(
                        connection,
                        playerUuid,
                        username,
                        ip,
                        !approvalRequired
                );

                connection.commit();
                connection.setAutoCommit(true);

                if (approvalRequired) {
                    deny(event, "approval-required");
                    audit(playerUuid, username, ip,
                            "NEW_ACCOUNT_PENDING", "Waiting for admin approval");
                    alertAdmins(username, "New account requires approval");
                    return;
                }

                if (plugin.getConfig().getBoolean(
                        "settings.log-successful-logins", true)) {
                    audit(playerUuid, username, ip,
                            "ACCOUNT_REGISTERED", "New account registered");
                }

            } catch (SQLException exception) {
                try {
                    connection.rollback();
                    connection.setAutoCommit(true);
                } catch (SQLException rollbackException) {
                    exception.addSuppressed(rollbackException);
                }

                plugin.getLogger().log(
                        Level.SEVERE,
                        "Account verification failed for " + username,
                        exception
                );

                handleDatabaseFailure(event);
            }
        }
    }

    private boolean isBanned(Connection connection, String uuid)
            throws SQLException {
        String sql = "SELECT 1 FROM account_bans WHERE player_uuid = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private boolean isAuthorizedAccount(
            Connection connection,
            String uuid,
            String ip
    ) throws SQLException {
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
            Connection connection,
            String uuid,
            String username,
            String ip
    ) throws SQLException {
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

        String now = Instant.now().toString();

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);
            statement.setString(2, username);
            statement.setString(3, ip);
            statement.setString(4, now);
            statement.setString(5, now);
            statement.executeUpdate();
        }
    }

    private AccountRecord getAccount(
            Connection connection,
            String uuid
    ) throws SQLException {
        String sql = """
                SELECT ip_address, approved
                FROM accounts
                WHERE uuid = ?
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);

            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }

                return new AccountRecord(
                        result.getString("ip_address"),
                        result.getInt("approved")
                );
            }
        }
    }

    private int getIpLimit(
            Connection connection,
            String ip,
            int defaultLimit
    ) throws SQLException {
        String sql = "SELECT max_accounts FROM ip_limits WHERE ip_address = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, ip);

            try (ResultSet result = statement.executeQuery()) {
                return result.next()
                        ? Math.max(1, result.getInt("max_accounts"))
                        : defaultLimit;
            }
        }
    }

    private int countApprovedAccounts(
            Connection connection,
            String ip
    ) throws SQLException {
        String sql = """
                SELECT COUNT(*)
                FROM accounts
                WHERE ip_address = ? AND approved = 1
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, ip);

            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getInt(1) : 0;
            }
        }
    }

    private void insertAccount(
            Connection connection,
            String uuid,
            String username,
            String ip,
            boolean approved
    ) throws SQLException {
        String sql = """
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """;

        String now = Instant.now().toString();

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
            Connection connection,
            String uuid,
            String username,
            String ip,
            boolean approved
    ) throws SQLException {
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
            Connection connection,
            String uuid,
            String username
    ) throws SQLException {
        String sql = """
                UPDATE accounts
                SET username = ?, last_seen = ?
                WHERE uuid = ?
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            statement.setString(2, Instant.now().toString());
            statement.setString(3, uuid);
            statement.executeUpdate();
        }
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

    private void deny(PlayerLoginEvent event, String messageKey) {
        event.disallow(
                PlayerLoginEvent.Result.KICK_OTHER,
                plugin.getMessage(messageKey)
        );
    }

    private void handleDatabaseFailure(PlayerLoginEvent event) {
        boolean failClosed = plugin.getConfig().getBoolean(
                "security.fail-closed-on-database-error", true);

        if (failClosed) {
            deny(event, "database-error");
        } else {
            plugin.getLogger().warning(
                    "Database error; login allowed because fail-closed is disabled."
            );
        }
    }

    private void alertAdmins(String username, String reason) {
        if (!plugin.getConfig().getBoolean("settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(plugin.getMessage(
                            "admin-blocked-login"
                    ).replace("{player}", username)
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
                    


package com.pritamx.thunderantialt;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

public final class AccountListener implements Listener {

    private final ThunderAntiAlt plugin;

    public AccountListener(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        Player player = event.getPlayer();

        if (player.hasPermission("thunderantialt.bypass")) {
            return;
        }

        InetAddress address = event.getAddress();
        if (address == null) {
            block(event, "Unable to verify your IP address.");
            return;
        }

        String ip = address.getHostAddress();
        String uuid = player.getUniqueId().toString();
        String username = player.getName();

        Connection database = plugin.getDatabase();

        if (database == null) {
            block(event, "Account verification unavailable. Contact an administrator.");
            return;
        }

        synchronized (database) {
            try {
                boolean exists = false;
                String savedIp = null;
                int approved = 0;

                try (PreparedStatement query = database.prepareStatement(
                        "SELECT ip_address, approved FROM accounts WHERE uuid = ?")) {

                    query.setString(1, uuid);

                    try (ResultSet result = query.executeQuery()) {
                        if (result.next()) {
                            exists = true;
                            savedIp = result.getString("ip_address");
                            approved = result.getInt("approved");
                        }
                    }
                }

                // Existing accounts must use their bound IP.
                if (exists && (savedIp == null || !savedIp.equals(ip))) {
                    logEvent(database, uuid, username, ip,
                            "NEW_IP_BLOCKED",
                            "Account attempted login from a different IP");

                    alertAdmins(username, "Blocked login attempt");

                    block(event,
                            "Your IP has changed. Ask an administrator to reset your binding.");
                    return;
                }

                // Existing accounts cannot bypass pending approval.
                if (exists && approved != 1) {
                    logEvent(database, uuid, username, ip,
                            "APPROVAL_PENDING",
                            "Login blocked while awaiting administrator approval");

                    alertAdmins(username, "Login awaiting approval");

                    block(event,
                            "Your account is awaiting administrator approval.");
                    return;
                }

                if (!exists) {
                    int limit = Math.max(1,
                            plugin.getConfig().getInt(
                                    "settings.max-accounts-per-ip", 1));

                    int count;

                    try (PreparedStatement query = database.prepareStatement(
                            "SELECT COUNT(*) FROM accounts WHERE ip_address = ?")) {
                        query.setString(1, ip);

                        try (ResultSet result = query.executeQuery()) {
                            count = result.next() ? result.getInt(1) : 0;
                        }
                    }

                    if (count >= limit) {
                        logEvent(database, uuid, username, ip,
                                "ACCOUNT_LIMIT_BLOCKED",
                                "Configured IP account limit reached");

                        alertAdmins(username, "Blocked login attempt");

                        block(event,
                                "This IP has reached the account limit.");
                        return;
                    }

                    boolean approvalRequired = plugin.getConfig()
                            .getBoolean("settings.require-new-ip-approval", true);

                    int isApproved = approvalRequired ? 0 : 1;

                    try (PreparedStatement insert = database.prepareStatement("""
                            INSERT INTO accounts
                            (uuid, username, ip_address, account_limit,
                             approved, last_seen)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """)) {

                        insert.setString(1, uuid);
                        insert.setString(2, username);
                        insert.setString(3, ip);
                        insert.setInt(4, limit);
                        insert.setInt(5, isApproved);
                        insert.setString(6, Instant.now().toString());
                        insert.executeUpdate();
                    }

                    logEvent(database, uuid, username, ip,
                            "NEW_ACCOUNT",
                            approvalRequired
                                    ? "New account awaiting approval"
                                    : "New account registered");

                    alertAdmins(username, "New account detected");

                    if (approvalRequired) {
                        block(event,
                                "Your account requires administrator approval.");
                        return;
                    }

                } else {
                    try (PreparedStatement update = database.prepareStatement(
                            "UPDATE accounts SET username = ?, last_seen = ? WHERE uuid = ?")) {

                        update.setString(1, username);
                        update.setString(2, Instant.now().toString());
                        update.setString(3, uuid);
                        update.executeUpdate();
                    }

                    if (plugin.getConfig().getBoolean(
                            "settings.log-successful-logins", true)) {
                        logEvent(database, uuid, username, ip,
                                "LOGIN_ALLOWED", "Existing account login accepted");
                    }
                }

            } catch (SQLException exception) {
                plugin.getLogger().severe(
                        "Account verification failed: "
                                + exception.getMessage());

                block(event,
                        "Account verification failed. Contact an administrator.");
            }
        }
    }

    private void block(PlayerLoginEvent event, String message) {
        event.disallow(
                PlayerLoginEvent.Result.KICK_OTHER,
                message
        );
    }

    private void logEvent(
            Connection database,
            String uuid,
            String username,
            String ip,
            String action,
            String details) throws SQLException {

        boolean blocked = action.contains("BLOCKED")
                || action.equals("APPROVAL_PENDING");

        if (blocked && !plugin.getConfig().getBoolean(
                "settings.log-blocked-attempts", true)) {
            return;
        }

        try (PreparedStatement query = database.prepareStatement("""
                INSERT INTO audit_logs
                (player_uuid, username, ip_address, event, details)
                VALUES (?, ?, ?, ?, ?)
                """)) {

            query.setString(1, uuid);
            query.setString(2, username);
            query.setString(3, ip);
            query.setString(4, action);
            query.setString(5, details);
            query.executeUpdate();
        }
    }

    private void alertAdmins(String username, String reason) {
        if (!plugin.getConfig().getBoolean("settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(
                            "§8[§6ThunderAntiAlt§8] §e"
                                    + reason + ": §f" + username);
                }
            }
        });
    }
}

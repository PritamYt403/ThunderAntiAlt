package com.pritamx.thunderantialt;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
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
            event.disallow(
                    PlayerLoginEvent.Result.KICK_OTHER,
                    "Unable to verify your connection."
            );
            return;
        }

        String ip = address.getHostAddress();
        String uuid = player.getUniqueId().toString();
        Connection database = plugin.getDatabase();

        if (database == null) {
            event.disallow(
                    PlayerLoginEvent.Result.KICK_OTHER,
                    "Account verification is unavailable. Contact an administrator."
            );
            return;
        }

        try {
            database.setAutoCommit(false);

            String savedIp = null;

            try (PreparedStatement query = database.prepareStatement(
                    "SELECT ip_address FROM accounts WHERE uuid = ?")) {
                query.setString(1, uuid);

                try (ResultSet result = query.executeQuery()) {
                    if (result.next()) {
                        savedIp = result.getString("ip_address");
                    }
                }
            }

            if (savedIp != null && !savedIp.equals(ip)) {
                logAttempt(database, uuid, player.getName(), ip,
                        "NEW_IP_BLOCKED", "Account used from a different IP");
                database.commit();

                event.disallow(
                        PlayerLoginEvent.Result.KICK_OTHER,
                        "Your IP has changed. Ask an administrator to reset your binding."
                );
                return;
            }

            if (savedIp == null) {
                int limit = Math.max(
                        1, plugin.getConfig().getInt("settings.max-accounts-per-ip", 1));

                int count;

                try (PreparedStatement query = database.prepareStatement(
                        "SELECT COUNT(*) FROM accounts WHERE ip_address = ?")) {
                    query.setString(1, ip);

                    try (ResultSet result = query.executeQuery()) {
                        count = result.next() ? result.getInt(1) : 0;
                    }
                }

                if (count >= limit) {
                    logAttempt(database, uuid, player.getName(), ip,
                            "ACCOUNT_LIMIT_BLOCKED", "IP account limit reached");
                    database.commit();

                    event.disallow(
                            PlayerLoginEvent.Result.KICK_OTHER,
                            "This IP has reached the account limit."
                    );
                    return;
                }

                boolean approved =
                        !plugin.getConfig().getBoolean(
                                "settings.require-new-ip-approval", true);

                try (PreparedStatement insert = database.prepareStatement("""
                        INSERT INTO accounts
                        (uuid, username, ip_address, account_limit, approved, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """)) {
                    insert.setString(1, uuid);
                    insert.setString(2, player.getName());
                    insert.setString(3, ip);
                    insert.setInt(4, limit);
                    insert.setInt(5, approved ? 1 : 0);
                    insert.setString(6, Instant.now().toString());
                    insert.executeUpdate();
                }

                logAttempt(database, uuid, player.getName(), ip,
                        "NEW_ACCOUNT", "New account detected");
                database.commit();

                if (!approved) {
                    event.disallow(
                            PlayerLoginEvent.Result.KICK_OTHER,
                            "Your account requires administrator approval."
                    );
                    return;
                }

                alertAdmins(player.getName());
            } else {
                try (PreparedStatement update = database.prepareStatement(
                        "UPDATE accounts SET username = ?, last_seen = ? WHERE uuid = ?")) {
                    update.setString(1, player.getName());
                    update.setString(2, Instant.now().toString());
                    update.setString(3, uuid);
                    update.executeUpdate();
                }

                database.commit();
            }

        } catch (SQLException exception) {
            try {
                database.rollback();
            } catch (SQLException ignored) {
                // Keep the login blocked if verification fails.
            }

            plugin.getLogger().severe(
                    "Account verification failed: " + exception.getMessage());

            event.disallow(
                    PlayerLoginEvent.Result.KICK_OTHER,
                    "Account verification failed. Contact an administrator."
            );
        } finally {
            try {
                database.setAutoCommit(true);
            } catch (SQLException ignored) {
                // Database may already be unavailable.
            }
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        // Additional join handling can be added here.
    }

    private void logAttempt(
            Connection database,
            String uuid,
            String username,
            String ip,
            String action,
            String details) throws SQLException {

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

    private void alertAdmins(String username) {
        if (!plugin.getConfig().getBoolean("settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(
                            "§8[§6ThunderAntiAlt§8] §eNew account detected: §f"
                                    + username);
                }
            }
        });
    }
                           }

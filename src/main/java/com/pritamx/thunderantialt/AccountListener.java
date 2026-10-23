
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
            deny(event, "Unable to verify your IP address.");
            return;
        }

        String ip = address.getHostAddress();
        String uuid = player.getUniqueId().toString();
        String username = player.getName();
        Connection db = plugin.getDatabase();

        if (db == null) {
            deny(event, "Account verification unavailable. Contact an administrator.");
            return;
        }

        synchronized (db) {
            try {
                db.setAutoCommit(false);

                boolean exists = false;
                String savedIp = null;
                int approved = 0;

                try (PreparedStatement ps = db.prepareStatement(
                        "SELECT ip_address, approved FROM accounts WHERE uuid = ?")) {
                    ps.setString(1, uuid);

                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            exists = true;
                            savedIp = rs.getString("ip_address");
                            approved = rs.getInt("approved");
                        }
                    }
                }

                if (exists) {
                    if (savedIp == null || !savedIp.equals(ip)) {
                        log(db, uuid, username, ip, "NEW_IP_BLOCKED",
                                "Account attempted login from a different IP");
                        db.commit();
                        alertAdmins(username, "Blocked login attempt");
                        deny(event, "Your IP has changed. Ask an administrator to reset your binding.");
                        return;
                    }

                    boolean approvedExtra = isAuthorizedForOwnerIp(db, uuid, ip);

                    if (approved != 1 && !approvedExtra) {
                        log(db, uuid, username, ip, "APPROVAL_PENDING",
                                "Account awaits administrator approval");
                        db.commit();
                        alertAdmins(username, "Account awaiting approval");
                        deny(event, "Your account is awaiting administrator approval.");
                        return;
                    }

                    updateLastSeen(db, uuid, username);

                    if (plugin.getConfig().getBoolean(
                            "settings.log-successful-logins", true)) {
                        log(db, uuid, username, ip, "LOGIN_ALLOWED",
                                approvedExtra && approved != 1
                                        ? "Authorized extra account login accepted"
                                        : "Existing account login accepted");
                    }

                    db.commit();
                    return;
                }

                boolean authorizedExtra = isAuthorizedForOwnerIp(db, uuid, ip);

                int limit = Math.max(1, plugin.getConfig().getInt(
                        "settings.max-accounts-per-ip", 1));

                int count;
                try (PreparedStatement ps = db.prepareStatement(
                        "SELECT COUNT(*) FROM accounts WHERE ip_address = ?")) {
                    ps.setString(1, ip);

                    try (ResultSet rs = ps.executeQuery()) {
                        count = rs.next() ? rs.getInt(1) : 0;
                    }
                }

                if (count >= limit && !authorizedExtra) {
                    log(db, uuid, username, ip, "ACCOUNT_LIMIT_BLOCKED",
                            "Configured IP account limit reached");
                    db.commit();
                    alertAdmins(username, "Blocked login attempt");
                    deny(event, "This IP has reached the account limit.");
                    return;
                }

                boolean approvalRequired = plugin.getConfig().getBoolean(
                        "settings.require-new-ip-approval", true);

                int isApproved = approvalRequired ? 0 : 1;

                try (PreparedStatement ps = db.prepareStatement("""
                        INSERT INTO accounts
                        (uuid, username, ip_address, account_limit, approved, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """)) {
                    ps.setString(1, uuid);
                    ps.setString(2, username);
                    ps.setString(3, ip);
                    ps.setInt(4, limit);
                    ps.setInt(5, isApproved);
                    ps.setString(6, Instant.now().toString());
                    ps.executeUpdate();
                }

                log(db, uuid, username, ip, "NEW_ACCOUNT",
                        "New account registered");

                db.commit();

                if (approvalRequired) {
                    alertAdmins(username, "New account awaiting approval");
                    deny(event, "Your account requires administrator approval.");
                } else {
                    alertAdmins(username, "New account detected");
                }

            } catch (SQLException exception) {
                try {
                    db.rollback();
                } catch (SQLException rollbackError) {
                    plugin.getLogger().severe(
                            "Database rollback failed: "
                                    + rollbackError.getMessage());
                }

                plugin.getLogger().severe(
                        "Account verification failed: "
                                + exception.getMessage());

                deny(event, "Account verification failed. Contact an administrator.");
            } finally {
                try {
                    db.setAutoCommit(true);
                } catch (SQLException exception) {
                    plugin.getLogger().severe(
                            "Could not restore database transaction mode.");
                }
            }
        }
    }

    private boolean isAuthorizedForOwnerIp(
            Connection db, String accountUuid, String loginIp)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1
                FROM authorized_accounts aa
                JOIN accounts owner ON owner.uuid = aa.owner_uuid
                WHERE aa.account_uuid = ?
                  AND owner.ip_address = ?
                LIMIT 1
                """)) {

            ps.setString(1, accountUuid);
            ps.setString(2, loginIp);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private void updateLastSeen(
            Connection db, String uuid, String username)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement(
                "UPDATE accounts SET username = ?, last_seen = ? WHERE uuid = ?")) {

            ps.setString(1, username);
            ps.setString(2, Instant.now().toString());
            ps.setString(3, uuid);
            ps.executeUpdate();
        }
    }

    private void deny(PlayerLoginEvent event, String message) {
        event.disallow(PlayerLoginEvent.Result.KICK_OTHER, message);
    }

    private void log(
            Connection db,
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

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO audit_logs
                (player_uuid, username, ip_address, event, details)
                VALUES (?, ?, ?, ?, ?)
                """)) {

            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, action);
            ps.setString(5, details);
            ps.executeUpdate();
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

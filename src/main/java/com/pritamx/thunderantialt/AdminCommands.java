
package com.pritamx.thunderantialt;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public final class AdminCommands implements CommandExecutor {

    private final ThunderAntiAlt plugin;

    public AdminCommands(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(
            CommandSender sender,
            Command command,
            String label,
            String[] args) {

        if (!sender.hasPermission("thunderantialt.admin")) {
            send(sender, "&cYou don't have permission.");
            return true;
        }

        if (args.length == 0) {
            help(sender);
            return true;
        }

        if (args[0].equalsIgnoreCase("reload")) {
            plugin.reloadConfig();
            send(sender, "&aConfiguration reloaded.");
            return true;
        }

        Connection db = plugin.getDatabase();

        if (db == null) {
            send(sender, "&cDatabase unavailable.");
            return true;
        }

        try {
            switch (args[0].toLowerCase()) {
                case "approve" -> {
                    if (requireArgs(sender, args, 2)) {
                        approve(sender, db, args[1]);
                    }
                }

                case "info" -> {
                    if (requireArgs(sender, args, 2)) {
                        info(sender, db, args[1], false);
                    }
                }

                case "lookup" -> {
                    if (requireArgs(sender, args, 2)) {
                        info(sender, db, args[1], true);
                    }
                }

                case "logs" -> {
                    if (requireArgs(sender, args, 2)) {
                        logs(sender, db, args[1]);
                    }
                }

                case "adduser" -> {
                    if (requireArgs(sender, args, 3)) {
                        authorize(sender, db, args[1], args[2], true);
                    }
                }

                case "removeuser" -> {
                    if (requireArgs(sender, args, 3)) {
                        authorize(sender, db, args[1], args[2], false);
                    }
                }

                case "reset" -> {
                    if (requireArgs(sender, args, 2)) {
                        reset(sender, db, args[1]);
                    }
                }

                case "unban" -> {
                    if (requireArgs(sender, args, 2)) {
                        approve(sender, db, args[1]);
                    }
                }

                case "limit" -> {
                    if (requireArgs(sender, args, 3)) {
                        setLimit(sender, db, args[1], args[2]);
                    }
                }

                default -> help(sender);
            }
        } catch (SQLException exception) {
            plugin.getLogger().severe(
                    "Admin command database error: "
                            + exception.getMessage());
            send(sender, "&cDatabase error. Check server logs.");
        }

        return true;
    }

    private void approve(
            CommandSender sender, Connection db, String username)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement(
                "UPDATE accounts SET approved = 1 WHERE LOWER(username) = LOWER(?)")) {
            ps.setString(1, username);

            if (ps.executeUpdate() == 0) {
                send(sender, "&cAccount not found: " + username);
            } else {
                audit(db, username, "ADMIN_APPROVE",
                        "Account approved by " + sender.getName());
                send(sender, "&aAccount approved: &f" + username);
            }
        }
    }

    private void info(
            CommandSender sender,
            Connection db,
            String username,
            boolean showFullIp) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address, approved,
                       account_limit, created_at, last_seen
                FROM accounts
                WHERE LOWER(username) = LOWER(?)
                """)) {

            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    send(sender, "&cAccount not found.");
                    return;
                }

                send(sender, "&6--- ThunderAntiAlt Account ---");
                send(sender, "&eUsername: &f" + rs.getString("username"));
                send(sender, "&eUUID: &f" + rs.getString("uuid"));

                String ip = rs.getString("ip_address");
                send(sender, "&eIP: &f" +
                        (showFullIp ? safeIp(ip) : maskIp(ip)));

                send(sender, "&eApproved: &f" +
                        (rs.getInt("approved") == 1 ? "Yes" : "No"));

                send(sender, "&eAccount limit: &f" +
                        rs.getInt("account_limit"));

                send(sender, "&eCreated: &f" +
                        rs.getString("created_at"));

                send(sender, "&eLast seen: &f" +
                        rs.getString("last_seen"));
            }
        }
    }

    private void logs(
            CommandSender sender, Connection db, String username)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT event, details, ip_address, created_at
                FROM audit_logs
                WHERE LOWER(username) = LOWER(?)
                ORDER BY id DESC
                LIMIT 20
                """)) {

            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {
                send(sender, "&6--- Recent Audit Logs ---");

                int count = 0;

                while (rs.next()) {
                    count++;

                    send(sender, "&e" + rs.getString("event")
                            + " &7- " + rs.getString("details"));

                    send(sender, "&7IP: " +
                            safeIp(rs.getString("ip_address"))
                            + " | " + rs.getString("created_at"));
                }

                if (count == 0) {
                    send(sender, "&7No logs found.");
                }
            }
        }
    }

    private void authorize(
            CommandSender sender,
            Connection db,
            String ownerName,
            String accountName,
            boolean add) throws SQLException {

        String ownerUuid = findUuid(db, ownerName);
        String accountUuid = findUuid(db, accountName);

        if (ownerUuid == null || accountUuid == null) {
            send(sender,
                    "&cBoth accounts must exist in the database first.");
            return;
        }

        if (ownerUuid.equals(accountUuid)) {
            send(sender, "&cChoose two different accounts.");
            return;
        }

        if (add) {
            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT OR IGNORE INTO authorized_accounts
                    (owner_uuid, account_uuid)
                    VALUES (?, ?)
                    """)) {

                ps.setString(1, ownerUuid);
                ps.setString(2, accountUuid);

                int changed = ps.executeUpdate();

                send(sender, changed == 1
                        ? "&aExtra-account authorization recorded."
                        : "&eThis authorization already exists.");

                audit(db, ownerName, "ADMIN_ADDUSER",
                        accountName + " authorized by " + sender.getName());
            }
        } else {
            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM authorized_accounts
                    WHERE owner_uuid = ? AND account_uuid = ?
                    """)) {

                ps.setString(1, ownerUuid);
                ps.setString(2, accountUuid);

                int changed = ps.executeUpdate();

                send(sender, changed == 1
                        ? "&aAuthorization removed."
                        : "&cAuthorization not found.");

                audit(db, ownerName, "ADMIN_REMOVEUSER",
                        accountName + " authorization changed by "
                                + sender.getName());
            }
        }
    }

    private void reset(
            CommandSender sender, Connection db, String username)
            throws SQLException {

        String uuid = findUuid(db, username);

        if (uuid == null) {
            send(sender, "&cAccount not found.");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement(
                "DELETE FROM accounts WHERE uuid = ?")) {

            ps.setString(1, uuid);
            ps.executeUpdate();
        }

        audit(db, username, "ADMIN_RESET",
                "Account binding reset by " + sender.getName());

        send(sender,
                "&aAccount binding cleared. The player must register again.");
    }

    private void setLimit(
            CommandSender sender,
            Connection db,
            String username,
            String value) throws SQLException {

        int limit;

        try {
            limit = Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            send(sender, "&cEnter a valid number.");
            return;
        }

        if (limit < 1 || limit > 100) {
            send(sender, "&cLimit must be between 1 and 100.");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement(
                "UPDATE accounts SET account_limit = ? WHERE LOWER(username) = LOWER(?)")) {

            ps.setInt(1, limit);
            ps.setString(2, username);

            if (ps.executeUpdate() == 0) {
                send(sender, "&cAccount not found.");
            } else {
                audit(db, username, "ADMIN_LIMIT",
                        "Limit set to " + limit + " by " + sender.getName());
                send(sender, "&aStored account limit: &f" + limit);
            }
        }
    }

    private String findUuid(Connection db, String username)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement(
                "SELECT uuid FROM accounts WHERE LOWER(username) = LOWER(?)")) {

            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("uuid") : null;
            }
        }
    }

    private void audit(
            Connection db,
            String username,
            String event,
            String details) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO audit_logs (username, event, details)
                VALUES (?, ?, ?)
                """)) {

            ps.setString(1, username);
            ps.setString(2, event);
            ps.setString(3, details);
            ps.executeUpdate();
        }
    }

    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "Unknown";
        }

        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".***.***";
            }
        }

        if (ip.contains(":")) {
            int index = ip.lastIndexOf(':');
            return ip.substring(0, index) + ":****";
        }

        return "Hidden";
    }

    private String safeIp(String ip) {
        return ip == null || ip.isBlank() ? "Unknown" : ip;
    }

    private boolean requireArgs(
            CommandSender sender, String[] args, int count) {

        if (args.length != count) {
            help(sender);
            return false;
        }

        return true;
    }

    private void help(CommandSender sender) {
        send(sender, "&6--- ThunderAntiAlt Commands ---");
        send(sender, "&e/ta approve <player>");
        send(sender, "&e/ta info <player>");
        send(sender, "&e/ta lookup <player>");
        send(sender, "&e/ta logs <player>");
        send(sender, "&e/ta adduser <owner> <account>");
        send(sender, "&e/ta removeuser <owner> <account>");
        send(sender, "&e/ta reset <player>");
        send(sender, "&e/ta unban <player>");
        send(sender, "&e/ta limit <player> <number>");
        send(sender, "&e/ta reload");
    }

    private void send(CommandSender sender, String message) {
        sender.sendMessage(
                ChatColor.translateAlternateColorCodes('&',
                        "&8[&6ThunderAntiAlt&8] " + message));
    }
}

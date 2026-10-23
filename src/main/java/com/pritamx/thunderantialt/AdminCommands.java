
package com.pritamx.thunderantialt;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;

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
            String[] args
    ) {
        if (!sender.hasPermission("thunderantialt.admin")) {
            plugin.sendMessage(sender, "no-permission");
            return true;
        }

        if (args.length == 0 || args[0].equalsIgnoreCase("help")) {
            showHelp(sender);
            return true;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection connection = plugin.getDatabaseConnection();

            if (connection == null) {
                plugin.sendMessage(sender, "database-error");
                return true;
            }

            try {
                switch (args[0].toLowerCase()) {
                    case "info" -> showInfo(sender, connection, args);
                    case "lookup" -> lookup(sender, connection, args);
                    case "logs" -> showLogs(sender, connection, args);
                    case "approve" -> approve(sender, connection, args);
                    case "adduser" -> addUser(sender, connection, args);
                    case "removeuser" -> removeUser(sender, connection, args);
                    case "reset" -> resetBinding(sender, connection, args);
                    case "ban" -> ban(sender, connection, args);
                    case "unban" -> unban(sender, connection, args);
                    case "limit" -> setLimit(sender, connection, args);
                    case "clearlogs" -> clearLogs(sender, connection, args);
                    case "reload" -> reload(sender);
                    default -> showHelp(sender);
                }
            } catch (SQLException exception) {
                plugin.getLogger().log(
                        Level.SEVERE,
                        "Admin command failed: " + args[0],
                        exception
                );
                plugin.sendMessage(sender, "database-error");
            }
        }

        return true;
    }

    private void showHelp(CommandSender sender) {
        sender.sendMessage(plugin.color("&6--- ThunderAntiAlt Commands ---"));
        sender.sendMessage(plugin.color("&e/ta info <player> &7- Account information"));
        sender.sendMessage(plugin.color("&e/ta lookup <player> &7- Full IP lookup"));
        sender.sendMessage(plugin.color("&e/ta logs <player> &7- Audit history"));
        sender.sendMessage(plugin.color("&e/ta approve <player> &7- Approve account"));
        sender.sendMessage(plugin.color("&e/ta adduser <player> <owner> &7- Authorize extra account"));
        sender.sendMessage(plugin.color("&e/ta removeuser <player> &7- Remove authorization"));
        sender.sendMessage(plugin.color("&e/ta reset <player> &7- Reset IP binding"));
        sender.sendMessage(plugin.color("&e/ta ban <player> [reason] &7- Ban account"));
        sender.sendMessage(plugin.color("&e/ta unban <player> &7- Remove account ban"));
        sender.sendMessage(plugin.color("&e/ta limit <player> <number> &7- Set IP account limit"));
        sender.sendMessage(plugin.color("&e/ta clearlogs <player> &7- Clear audit history"));
        sender.sendMessage(plugin.color("&e/ta reload &7- Reload configuration"));
    }

    private void showInfo(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta info <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String ip = account.ip == null ? "Not bound" : maskIp(account.ip);
        int limit = account.ip == null
                ? plugin.getConfig().getInt("settings.max-accounts-per-ip", 1)
                : getLimit(connection, account.ip);

        sender.sendMessage(plugin.color("&6--- ThunderAntiAlt Account Info ---"));
        sender.sendMessage(plugin.color("&ePlayer: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + account.uuid));
        sender.sendMessage(plugin.color("&eIP: &f" + ip));
        sender.sendMessage(plugin.color("&eApproved: &f" + (account.approved == 1)));
        sender.sendMessage(plugin.color("&eCreated: &f" + safe(account.createdAt)));
        sender.sendMessage(plugin.color("&eLast Seen: &f" + safe(account.lastSeen)));
        sender.sendMessage(plugin.color("&eIP Account Limit: &f" + limit));
        sender.sendMessage(plugin.color("&eBanned: &f" +
                isBanned(connection, account.uuid)));
    }

    private void lookup(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta lookup <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        sender.sendMessage(plugin.color("&6--- Full Account Lookup ---"));
        sender.sendMessage(plugin.color("&ePlayer: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + account.uuid));
        sender.sendMessage(plugin.color("&eFull IP: &f" +
                (account.ip == null ? "Not bound" : account.ip)));
        sender.sendMessage(plugin.color("&eApproved: &f" + (account.approved == 1)));

        plugin.logAudit(
                sender.getName().equals("CONSOLE") ? null : null,
                sender.getName(),
                null,
                "ADMIN_IP_LOOKUP",
                "Full IP lookup for " + account.username
        );
    }

    private void showLogs(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta logs <player>")) {
            return;
        }

        String sql = """
                SELECT username, action, details, created_at
                FROM audit_logs
                WHERE LOWER(username) = LOWER(?)
                ORDER BY id DESC
                LIMIT 20
                """;

        int count = 0;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, args[1]);

            try (ResultSet result = statement.executeQuery()) {
                sender.sendMessage(plugin.color(
                        "&6--- Audit Logs: " + args[1] + " ---"
                ));

                while (result.next()) {
                    count++;
                    sender.sendMessage(plugin.color(
                            "&7[" + safe(result.getString("created_at")) + "] "
                            + "&e" + safe(result.getString("action"))
                            + " &f" + safe(result.getString("details"))
                    ));
                }
            }
        }

        if (count == 0) {
            plugin.sendMessage(sender, "logs-empty");
        }
    }

    private void approve(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta approve <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE accounts SET approved = 1 WHERE uuid = ?")) {
            statement.setString(1, account.uuid);

            if (statement.executeUpdate() == 0) {
                plugin.sendMessage(sender, "player-not-found");
                return;
            }
        }

        auditAdmin(sender, account, "ACCOUNT_APPROVED", "Account approved");
        sender.sendMessage(plugin.color(
                "&aApproved account: &f" + account.username
        ));
    }

    private void addUser(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(
                sender, args, 3, "/ta adduser <player> <owner>"
        )) {
            return;
        }

        Account authorized = findAccount(connection, args[1]);
        Account owner = findAccount(connection, args[2]);

        if (authorized == null || owner == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (authorized.uuid.equals(owner.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA player cannot authorize their own account."
            ));
            return;
        }

        if (owner.approved != 1 || owner.ip == null) {
            sender.sendMessage(plugin.color(
                    "&cThe owner must have an approved account with an IP binding."
            ));
            return;
        }

        String sql = """
                INSERT INTO authorized_accounts
                    (owner_uuid, authorized_uuid, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(authorized_uuid) DO UPDATE SET
                    owner_uuid = excluded.owner_uuid,
                    created_at = excluded.created_at
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, owner.uuid);
            statement.setString(2, authorized.uuid);
            statement.setString(3, Instant.now().toString());
            statement.executeUpdate();
        }

        plugin.logAudit(
                authorized.uuid,
                authorized.username,
                authorized.ip,
                "ACCOUNT_AUTHORIZED",
                "Authorized by " + owner.username
        );

        sender.sendMessage(plugin.color(
                "&aAuthorized &f" + authorized.username
                + " &ato use owner &f" + owner.username + "'s IP."
        ));
    }

    private void removeUser(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta removeuser <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM authorized_accounts WHERE authorized_uuid = ?")) {
            statement.setString(1, account.uuid);

            if (statement.executeUpdate() == 0) {
                sender.sendMessage(plugin.color(
                        "&eThis account has no extra-account authorization."
                ));
                return;
            }
        }

        auditAdmin(
                sender,
                account,
                "AUTHORIZATION_REMOVED",
                "Extra-account authorization removed"
        );

        sender.sendMessage(plugin.color(
                "&aRemoved extra-account authorization for &f"
                + account.username
        ));
    }

    private void resetBinding(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta reset <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE accounts
                SET ip_address = NULL, approved = 0
                WHERE uuid = ?
                """)) {
            statement.setString(1, account.uuid);
            statement.executeUpdate();
        }

        auditAdmin(
                sender,
                account,
                "IP_BINDING_RESET",
                "IP binding reset; approval required"
        );

        sender.sendMessage(plugin.color(
                "&aReset IP binding for &f" + account.username
                + "&a. The next login requires approval."
        ));
    }

    private void ban(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta ban <player> [reason]")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String reason = args.length >= 3
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length))
                : "No reason provided";

        String sql = """
                INSERT INTO account_bans
                    (player_uuid, username, reason, banned_by, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(player_uuid) DO UPDATE SET
                    username = excluded.username,
                    reason = excluded.reason,
                    banned_by = excluded.banned_by,
                    created_at = excluded.created_at
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, account.uuid);
            statement.setString(2, account.username);
            statement.setString(3, reason);
            statement.setString(4, sender.getName());
            statement.setString(5, Instant.now().toString());
            statement.executeUpdate();
        }

        auditAdmin(sender, account, "ACCOUNT_BANNED", "Reason: " + reason);

        sender.sendMessage(plugin.color(
                "&cBanned &f" + account.username + "&c. Reason: " + reason
        ));

        if (plugin.getServer().getPlayer(UUID.fromString(account.uuid)) != null) {
            plugin.getServer().getPlayer(UUID.fromString(account.uuid))
                    .kickPlayer(plugin.color("&cYour account is banned. Reason: " + reason));
        }
    }

    private void unban(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta unban <player>")) {
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM account_bans WHERE player_uuid = ?")) {
            statement.setString(1, account.uuid);

            if (statement.executeUpdate() == 0) {
                sender.sendMessage(plugin.color("&eThis account is not banned."));
                return;
            }
        }

        auditAdmin(sender, account, "ACCOUNT_UNBANNED", "Ban removed");

        sender.sendMessage(plugin.color(
                "&aUnbanned account: &f" + account.username
        ));
    }

    private void setLimit(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(
                sender, args, 3, "/ta limit <player> <number>"
        )) {
            return;
        }

        int limit;

        try {
            limit = Integer.parseInt(args[2]);
        } catch (NumberFormatException exception) {
            plugin.sendMessage(sender, "invalid-number");
            return;
        }

        if (limit < 1 || limit > 1000) {
            sender.sendMessage(plugin.color(
                    "&cLimit must be between 1 and 1000."
            ));
            return;
        }

        Account account = findAccount(connection, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (account.ip == null) {
            sender.sendMessage(plugin.color(
                    "&cThis account has no IP binding. Reset or approve it first."
            ));
            return;
        }

        String sql = """
                INSERT INTO ip_limits
                    (ip_address, max_accounts, updated_by, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    max_accounts = excluded.max_accounts,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, account.ip);
            statement.setInt(2, limit);
            statement.setString(3, sender.getName());
            statement.setString(4, Instant.now().toString());
            statement.executeUpdate();
        }

        auditAdmin(
                sender,
                account,
                "IP_LIMIT_UPDATED",
                "IP account limit set to " + limit
        );

        sender.sendMessage(plugin.color(
                "&aIP account limit for &f" + account.username
                + " &ais now &f" + limit + "&a."
        ));
    }

    private void clearLogs(
            CommandSender sender,
            Connection connection,
            String[] args
    ) throws SQLException {
        if (!requireArgs(sender, args, 2, "/ta clearlogs <player>")) {
            return;
        }

        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM audit_logs WHERE LOWER(username) = LOWER(?)")) {
            statement.setString(1, args[1]);
            int deleted = statement.executeUpdate();

            sender.sendMessage(plugin.color(
                    "&aDeleted &f" + deleted
                    + " &aaudit log entries for &f" + args[1] + "&a."
            ));
        }
    }

    private void reload(CommandSender sender) {
        plugin.reloadPluginSettings();
        plugin.sendMessage(sender, "reload-success");
    }

    private Account findAccount(
            Connection connection,
            String username
    ) throws SQLException {
        String sql = """
                SELECT uuid, username, ip_address, approved, created_at, last_seen
                FROM accounts
                WHERE LOWER(username) = LOWER(?)
                ORDER BY last_seen DESC
                LIMIT 1
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);

            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }

                return new Account(
                        result.getString("uuid"),
                        result.getString("username"),
                        result.getString("ip_address"),
                        result.getInt("approved"),
                        result.getString("created_at"),
                        result.getString("last_seen")
                );
            }
        }
    }

    private int getLimit(Connection connection, String ip)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT max_accounts FROM ip_limits WHERE ip_address = ?")) {
            statement.setString(1, ip);

            try (ResultSet result = statement.executeQuery()) {
                return result.next()
                        ? result.getInt("max_accounts")
                        : plugin.getConfig().getInt(
                                "settings.max-accounts-per-ip", 1);
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

    private void auditAdmin(
            CommandSender sender,
            Account account,
            String action,
            String details
    ) {
        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                action,
                "By " + sender.getName() + ": " + details
        );
    }

    private boolean requireArgs(
            CommandSender sender,
            String[] args,
            int minimum,
            String usage
    ) {
        if (args.length < minimum) {
            sender.sendMessage(plugin.color("&eUsage: " + usage));
            return false;
        }

        return true;
    }

    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "Not bound";
        }

        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".***.***";
            }
        }

        int lastColon = ip.lastIndexOf(':');
        return lastColon > 0 ? ip.substring(0, lastColon) + ":****" : "****";
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? "N/A" : value;
    }

    private static final class Account {
        private final String uuid;
        private final String username;
        private final String ip;
        private final int approved;
        private final String createdAt;
        private final String lastSeen;

        private Account(
                String uuid,
                String username,
                String ip,
                int approved,
                String createdAt,
                String lastSeen
        ) {
            this.uuid = uuid;
            this.username = username;
            this.ip = ip;
            this.approved = approved;
            this.createdAt = createdAt;
            this.lastSeen = lastSeen;
        }
    }
}

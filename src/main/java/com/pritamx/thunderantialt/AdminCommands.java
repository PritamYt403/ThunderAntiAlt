
package com.pritamx.thunderantialt;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

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
        if (!sender.isOp()
                && !sender.hasPermission("thunderantialt.admin")) {
            plugin.sendMessage(sender, "no-permission");
            return true;
        }

        if (args.length == 0) {
            help(sender);
            return true;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection db = plugin.getDatabaseConnection();

            if (db == null) {
                plugin.sendMessage(sender, "database-error");
                return true;
            }

            try {
                switch (args[0].toLowerCase(Locale.ROOT)) {
                    case "help" -> help(sender);
                    case "pending" -> pending(sender, db);
                    case "approve" -> approve(sender, db, args);
                    case "deny" -> deny(sender, db, args);
                    case "info" -> info(sender, db, args);
                    case "lookup" -> lookup(sender, db, args);
                    case "logs" -> logs(sender, db, args);
                    case "adduser" -> addUser(sender, db, args);
                    case "removeuser" -> removeUser(sender, db, args);
                    case "reset" -> reset(sender, db, args);
                    case "ban" -> ban(sender, db, args);
                    case "unban" -> unban(sender, db, args);
                    case "limit" -> limit(sender, db, args);
                    case "clearlogs" -> clearLogs(sender, db, args);
                    case "reload" -> {
                        plugin.reloadPluginSettings();
                        plugin.sendMessage(sender, "reload-success");
                    }
                    default -> plugin.sendMessage(sender, "unknown-command");
                }
            } catch (SQLException exception) {
                plugin.getLogger().severe(
                        "Command failed: " + exception.getMessage());
                plugin.sendMessage(sender, "database-error");
            }
        }

        return true;
    }

    private void help(CommandSender sender) {
        sender.sendMessage(plugin.color("&6--- ThunderAntiAlt Commands ---"));
        sender.sendMessage(plugin.color("&e/ta pending &7- Pending alt list"));
        sender.sendMessage(plugin.color("&e/ta approve <player> &7- Approve account"));
        sender.sendMessage(plugin.color("&e/ta deny <player> &7- Deny pending account"));
        sender.sendMessage(plugin.color("&e/ta info <player> &7- Account information"));
        sender.sendMessage(plugin.color("&e/ta lookup <player> &7- Account/IP lookup"));
        sender.sendMessage(plugin.color("&e/ta logs <player> &7- Audit history"));
        sender.sendMessage(plugin.color("&e/ta adduser <player> <owner> &7- Authorize extra account"));
        sender.sendMessage(plugin.color("&e/ta removeuser <player> &7- Remove authorization"));
        sender.sendMessage(plugin.color("&e/ta reset <player> &7- Reset IP binding"));
        sender.sendMessage(plugin.color("&e/ta ban <player> [reason] &7- Ban account"));
        sender.sendMessage(plugin.color("&e/ta unban <player> &7- Unban account"));
        sender.sendMessage(plugin.color("&e/ta limit <player> <number> &7- Set IP limit"));
        sender.sendMessage(plugin.color("&e/ta clearlogs <player> &7- Clear audit logs"));
        sender.sendMessage(plugin.color("&e/ta reload &7- Reload configuration"));
    }

    private void pending(CommandSender sender, Connection db)
            throws SQLException {
        String sql = """
                SELECT p.username, p.ip_address, p.main_uuid,
                       p.first_seen, p.attempts
                FROM pending_alt_accounts p
                WHERE p.status = 'PENDING'
                ORDER BY p.first_seen ASC
                """;

        sender.sendMessage(plugin.color("&6--- Pending Alt Approval List ---"));
        int count = 0;

        try (PreparedStatement ps = db.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                count++;
                sender.sendMessage(plugin.color(
                        "&e" + rs.getString("username")
                        + " &7| IP: &f" + rs.getString("ip_address")
                        + " &7| Main UUID: &f" + rs.getString("main_uuid")
                        + " &7| Attempts: &f" + rs.getInt("attempts")
                ));
            }
        }

        if (count == 0) {
            sender.sendMessage(plugin.color("&7No pending alt accounts."));
        } else {
            sender.sendMessage(plugin.color("&7Pending accounts: &f" + count));
        }
    }

    private void approve(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta approve <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        db.setAutoCommit(false);
        try {
            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 1, username = ?
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, account.username);
                ps.setString(2, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'APPROVED'
                    WHERE uuid = ? AND status = 'PENDING'
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT OR IGNORE INTO authorized_accounts
                        (owner_uuid, authorized_uuid, created_at)
                    SELECT main_uuid, uuid, ?
                    FROM pending_alt_accounts
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, Instant.now().toString());
                ps.setString(2, account.uuid);
                ps.executeUpdate();
            }

            db.commit();
        } catch (SQLException exception) {
            db.rollback();
            throw exception;
        } finally {
            db.setAutoCommit(true);
        }

        plugin.sendMessage(sender, "admin-account-approved",
                java.util.Map.of("player", account.username));
        plugin.logAudit(account.uuid, account.username, account.ip,
                "ACCOUNT_APPROVED", "Approved by " + sender.getName());
    }

    private void deny(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta deny <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE pending_alt_accounts
                SET status = 'DENIED'
                WHERE uuid = ? AND status = 'PENDING'
                """)) {
            ps.setString(1, account.uuid);
            if (ps.executeUpdate() == 0) {
                sender.sendMessage(plugin.color(
                        "&cThat account is not pending approval."));
                return;
            }
        }

        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE accounts SET approved = 0 WHERE uuid = ?
                """)) {
            ps.setString(1, account.uuid);
            ps.executeUpdate();
        }

        plugin.logAudit(account.uuid, account.username, account.ip,
                "ACCOUNT_DENIED", "Denied by " + sender.getName());
        sender.sendMessage(plugin.color(
                "&cDenied pending account: &f" + account.username));
    }

    private void info(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta info <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        int accountCount = 0;
        int pendingCount = 0;

        if (account.ip != null) {
            try (PreparedStatement ps = db.prepareStatement("""
                    SELECT COUNT(*) FROM accounts WHERE ip_address = ?
                    """)) {
                ps.setString(1, account.ip);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) accountCount = rs.getInt(1);
                }
            }
        }

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT COUNT(*) FROM pending_alt_accounts
                WHERE main_uuid = ? AND status = 'PENDING'
                """)) {
            ps.setString(1, account.uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) pendingCount = rs.getInt(1);
            }
        }

        sender.sendMessage(plugin.color("&6--- Account Information ---"));
        sender.sendMessage(plugin.color("&ePlayer: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + account.uuid));
        sender.sendMessage(plugin.color("&eIP: &f" + account.ip));
        sender.sendMessage(plugin.color("&eApproved: &f" + account.approved));
        sender.sendMessage(plugin.color("&eCreated: &f" + account.created));
        sender.sendMessage(plugin.color("&eLast Seen: &f" + account.lastSeen));

        // Only OP/admin can run this command.
        sender.sendMessage(plugin.color("&eAccounts on this IP: &f" + accountCount));
        sender.sendMessage(plugin.color("&ePending alts for this account: &f" + pendingCount));
    }

    private void lookup(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta lookup <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        sender.sendMessage(plugin.color("&6--- Account Lookup ---"));
        sender.sendMessage(plugin.color("&ePlayer: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + account.uuid));
        sender.sendMessage(plugin.color("&eIP: &f" + account.ip));
        sender.sendMessage(plugin.color("&eApproved: &f" + account.approved));

        if (account.ip != null) {
            try (PreparedStatement ps = db.prepareStatement("""
                    SELECT uuid, username, approved FROM accounts
                    WHERE ip_address = ?
                    ORDER BY created_at ASC
                    """)) {
                ps.setString(1, account.ip);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        sender.sendMessage(plugin.color(
                                "&7- &f" + rs.getString("username")
                                + " &7(UUID: " + rs.getString("uuid")
                                + ", approved=" + rs.getInt("approved") + ")"));
                    }
                }
            }
        }
    }

    private void logs(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta logs <player>");
            return;
        }

        sender.sendMessage(plugin.color("&6--- Audit Logs ---"));
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT username, action, details, created_at
                FROM audit_logs
                WHERE lower(username) = lower(?)
                ORDER BY id DESC LIMIT 20
                """)) {
            ps.setString(1, args[1]);
            try (ResultSet rs = ps.executeQuery()) {
                boolean found = false;
                while (rs.next()) {
                    found = true;
                    sender.sendMessage(plugin.color(
                            "&e" + rs.getString("created_at")
                            + " &7| &f" + rs.getString("action")
                            + " &7| " + rs.getString("details")));
                }
                if (!found) sender.sendMessage(plugin.color("&7No audit logs found."));
            }
        }
    }

    private void addUser(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 3) {
            usage(sender, "/ta adduser <player> <owner>");
            return;
        }

        Account player = findAccount(db, args[1]);
        Account owner = findAccount(db, args[2]);

        if (player == null || owner == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT OR REPLACE INTO authorized_accounts
                    (owner_uuid, authorized_uuid, created_at)
                VALUES (?, ?, ?)
                """)) {
            ps.setString(1, owner.uuid);
            ps.setString(2, player.uuid);
            ps.setString(3, Instant.now().toString());
            ps.executeUpdate();
        }

        sender.sendMessage(plugin.color("&aAuthorized " + player.username
                + " for owner " + owner.username + "."));
    }

    private void removeUser(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta removeuser <player>");
            return;
        }

        Account player = findAccount(db, args[1]);
        if (player == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                DELETE FROM authorized_accounts WHERE authorized_uuid = ?
                """)) {
            ps.setString(1, player.uuid);
            ps.executeUpdate();
        }

        sender.sendMessage(plugin.color("&aRemoved authorization for "
                + player.username + "."));
    }

    private void reset(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta reset <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE accounts SET ip_address = NULL, approved = 0
                WHERE uuid = ?
                """)) {
            ps.setString(1, account.uuid);
            ps.executeUpdate();
        }

        sender.sendMessage(plugin.color(
                "&aIP binding reset for " + account.username + "."));
    }

    private void ban(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta ban <player> [reason]");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String reason = args.length > 2
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length))
                : "Banned by administrator";

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT OR REPLACE INTO account_bans
                    (player_uuid, username, reason, banned_by, created_at)
                VALUES (?, ?, ?, ?, ?)
                """)) {
            ps.setString(1, account.uuid);
            ps.setString(2, account.username);
            ps.setString(3, reason);
            ps.setString(4, sender.getName());
            ps.setString(5, Instant.now().toString());
            ps.executeUpdate();
        }

        Player online = Bukkit.getPlayer(UUID.fromString(account.uuid));
        if (online != null) online.kickPlayer(plugin.color("&cBanned: " + reason));

        sender.sendMessage(plugin.color("&cBanned " + account.username + "."));
    }

    private void unban(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta unban <player>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                DELETE FROM account_bans WHERE player_uuid = ?
                """)) {
            ps.setString(1, account.uuid);
            ps.executeUpdate();
        }

        sender.sendMessage(plugin.color("&aUnbanned " + account.username + "."));
    }

    private void limit(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 3) {
            usage(sender, "/ta limit <player> <number>");
            return;
        }

        Account account = findAccount(db, args[1]);
        if (account == null || account.ip == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        int amount;
        try {
            amount = Integer.parseInt(args[2]);
        } catch (NumberFormatException exception) {
            plugin.sendMessage(sender, "invalid-number");
            return;
        }

        if (amount < 1) {
            plugin.sendMessage(sender, "invalid-number");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO ip_limits (ip_address, max_accounts, updated_by, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    max_accounts = excluded.max_accounts,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """)) {
            ps.setString(1, account.ip);
            ps.setInt(2, amount);
            ps.setString(3, sender.getName());
            ps.setString(4, Instant.now().toString());
            ps.executeUpdate();
        }

        sender.sendMessage(plugin.color("&aIP account limit set to "
                + amount + " for " + account.username + "."));
    }

    private void clearLogs(
            CommandSender sender, Connection db, String[] args)
            throws SQLException {
        if (args.length < 2) {
            usage(sender, "/ta clearlogs <player>");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                DELETE FROM audit_logs WHERE lower(username) = lower(?)
                """)) {
            ps.setString(1, args[1]);
            int removed = ps.executeUpdate();
            sender.sendMessage(plugin.color("&aCleared " + removed
                    + " audit log entries for " + args[1] + "."));
        }
    }

    private Account findAccount(Connection db, String username)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address, approved, created_at, last_seen
                FROM accounts
                WHERE lower(username) = lower(?)
                ORDER BY last_seen DESC LIMIT 1
                """)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return new Account(
                        rs.getString("uuid"),
                        rs.getString("username"),
                        rs.getString("ip_address"),
                        rs.getInt("approved"),
                        rs.getString("created_at"),
                        rs.getString("last_seen"));
            }
        }
    }

    private void usage(CommandSender sender, String text) {
        sender.sendMessage(plugin.color("&eUsage: " + text));
    }

    private static final class Account {
        final String uuid;
        final String username;
        final String ip;
        final int approved;
        final String created;
        final String lastSeen;

        Account(String uuid, String username, String ip, int approved,
                String created, String lastSeen) {
            this.uuid = uuid;
            this.username = username;
            this.ip = ip;
            this.approved = approved;
            this.created = created;
            this.lastSeen = lastSeen;
        }
    }
}

package com.pritamx.thunderantialt;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Locale;

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
            sendHelp(sender);
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

        if (!sub.equals("help")
                && !sub.equals("reload")
                && !sub.equals("adduser")
                && !sub.equals("info")
                && !sub.equals("pending")
                && !sub.equals("approve")
                && !sub.equals("deny")
                && !sub.equals("removeuser")
                && !sub.equals("limit")) {
            plugin.sendMessage(sender, "unknown-command");
            return true;
        }

        if (sub.equals("help")) {
            sendHelp(sender);
            return true;
        }

        if (sub.equals("reload")) {
            plugin.reloadPluginSettings();
            plugin.sendMessage(sender, "reload-success");
            return true;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection db = plugin.getDatabaseConnection();

            if (db == null) {
                plugin.sendMessage(sender, "database-error");
                return true;
            }

            try {
                switch (sub) {
                    case "pending" -> pending(sender, db);
                    case "approve" -> approve(sender, db, args);
                    case "deny" -> deny(sender, db, args);
                    case "info" -> info(sender, db, args);
                    case "adduser" -> addUser(sender, db, args);
                    case "removeuser" -> removeUser(sender, db, args);
                    case "limit" -> limit(sender, db, args);
                    default -> plugin.sendMessage(sender, "unknown-command");
                }
            } catch (SQLException ex) {
                plugin.getLogger().severe(
                        "Admin command database error: " + ex.getMessage());
                plugin.sendMessage(sender, "database-error");
            }
        }

        return true;
    }

    private void sendHelp(CommandSender sender) {
        plugin.sendMessage(sender, "help-header");
        plugin.sendMessage(sender, "help-reload");
        plugin.sendMessage(sender, "help-adduser");
        plugin.sendMessage(sender, "help-info");
        plugin.sendMessage(sender, "help-pending");
        plugin.sendMessage(sender, "help-approve");
        plugin.sendMessage(sender, "help-deny");
        plugin.sendMessage(sender, "help-removeuser");
        plugin.sendMessage(sender, "help-limit");
    }

    private void pending(CommandSender sender, Connection db)
            throws SQLException {
        sender.sendMessage(plugin.color("&6--- Pending Accounts ---"));

        int count = 0;

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT username, uuid, ip_address, main_uuid, attempts
                FROM pending_alt_accounts
                WHERE status = 'PENDING'
                ORDER BY first_seen ASC
                """);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                count++;

                sender.sendMessage(plugin.color(
                        "&e" + rs.getString("username")
                        + " &7| UUID: &f" + rs.getString("uuid")
                        + " &7| Main: &f" + rs.getString("main_uuid")
                        + " &7| IP: &f" + maskIp(rs.getString("ip_address"))
                        + " &7| Attempts: &f" + rs.getInt("attempts")));
            }
        }

        sender.sendMessage(plugin.color(
                count == 0
                        ? "&aNo pending accounts."
                        : "&ePending accounts: &f" + count));
    }

    private void approve(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 2) {
            usage(sender, "/ta approve <player>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cMain accounts cannot be approved as alt accounts."));
            return;
        }

        String mainUuid;

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT main_uuid
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {
            ps.setString(1, account.uuid);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    sender.sendMessage(plugin.color(
                            "&cNo pending relationship found for this player."));
                    return;
                }

                mainUuid = rs.getString("main_uuid");
            }
        }

        if (mainUuid == null
                || mainUuid.isBlank()
                || "UNKNOWN".equalsIgnoreCase(mainUuid)
                || mainUuid.equalsIgnoreCase(account.uuid)
                || !accountExists(db, mainUuid)
                || !isMain(db, mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cCannot approve: valid Main Account not found."));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {
            db.setAutoCommit(false);

            authorize(db, mainUuid, account.uuid);

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'APPROVED'
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 1, last_seen = ?
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, Instant.now().toString());
                ps.setString(2, account.uuid);
                ps.executeUpdate();
            }

            db.commit();
        } catch (SQLException ex) {
            rollback(db, ex);
            throw ex;
        } finally {
            db.setAutoCommit(oldAutoCommit);
        }

        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                "ACCOUNT_APPROVED",
                "Approved by " + sender.getName());

        sender.sendMessage(plugin.color(
                "&aApproved account: &f" + account.username));
    }

    private void deny(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 2) {
            usage(sender, "/ta deny <player>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cYou cannot deny a Main Account."));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {
            db.setAutoCommit(false);

            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT INTO pending_alt_accounts
                        (uuid, username, ip_address, main_uuid,
                         first_seen, last_seen, attempts, status)
                    VALUES (?, ?, ?, 'UNKNOWN', ?, ?, 1, 'DENIED')
                    ON CONFLICT(uuid) DO UPDATE SET
                        username = excluded.username,
                        status = 'DENIED',
                        last_seen = excluded.last_seen
                    """)) {
                String now = Instant.now().toString();

                ps.setString(1, account.uuid);
                ps.setString(2, account.username);
                ps.setString(3, account.ip == null ? "UNKNOWN" : account.ip);
                ps.setString(4, now);
                ps.setString(5, now);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM authorized_accounts
                    WHERE authorized_uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts SET approved = 0 WHERE uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            db.commit();
        } catch (SQLException ex) {
            rollback(db, ex);
            throw ex;
        } finally {
            db.setAutoCommit(oldAutoCommit);
        }

        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                "ACCOUNT_DENIED",
                "Denied by " + sender.getName());

        sender.sendMessage(plugin.color(
                "&cDenied account: &f" + account.username));
    }

    private void info(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 2) {
            usage(sender, "/ta info <player>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String status = account.approved == 1 ? "ACTIVE" : "PENDING";
        String mainUuid = "-";

        if (isMain(db, account.uuid)) {
            status = "MAIN";
            mainUuid = account.uuid;
        } else {
            try (PreparedStatement ps = db.prepareStatement("""
                    SELECT main_uuid, status
                    FROM pending_alt_accounts
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, account.uuid);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String value = rs.getString("main_uuid");

                        if (value != null
                                && !value.isBlank()
                                && !"UNKNOWN".equalsIgnoreCase(value)) {
                            mainUuid = value;
                        }

                        status = rs.getString("status");
                    }
                }
            }

            if (isAuthorized(db, account.uuid)) {
                status = "APPROVED";
            }
        }

        sender.sendMessage(plugin.color("&6--- Account Info ---"));
        sender.sendMessage(plugin.color("&ePlayer: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + account.uuid));
        sender.sendMessage(plugin.color("&eStatus: &f" + status));
        sender.sendMessage(plugin.color("&eMain UUID: &f" + mainUuid));
        sender.sendMessage(plugin.color("&eIP: &f" + maskIp(account.ip)));
        sender.sendMessage(plugin.color("&eCreated: &f" + account.created));
        sender.sendMessage(plugin.color("&eLast Seen: &f" + account.lastSeen));
    }

    private void addUser(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 3) {
            usage(sender, "/ta adduser <player> <owner>");
            return;
        }

        Account player = findAccount(db, args[1]);
        Account owner = findAccount(db, args[2]);

        if (player == null || owner == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (player.uuid.equalsIgnoreCase(owner.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA player cannot be their own alt."));
            return;
        }

        if (isMain(db, player.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot be registered as an alt."));
            return;
        }

        if (!isMain(db, owner.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cOwner must be a registered Main Account."));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {
            db.setAutoCommit(false);

            authorize(db, owner.uuid, player.uuid);

            String now = Instant.now().toString();

            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT INTO pending_alt_accounts
                        (uuid, username, ip_address, main_uuid,
                         first_seen, last_seen, attempts, status)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 'APPROVED')
                    ON CONFLICT(uuid) DO UPDATE SET
                        username = excluded.username,
                        ip_address = excluded.ip_address,
                        main_uuid = excluded.main_uuid,
                        last_seen = excluded.last_seen,
                        status = 'APPROVED'
                    """)) {
                ps.setString(1, player.uuid);
                ps.setString(2, player.username);
                ps.setString(3, player.ip == null ? "UNKNOWN" : player.ip);
                ps.setString(4, owner.uuid);
                ps.setString(5, now);
                ps.setString(6, now);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 1
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, player.uuid);
                ps.executeUpdate();
            }

            db.commit();
        } catch (SQLException ex) {
            rollback(db, ex);
            throw ex;
        } finally {
            db.setAutoCommit(oldAutoCommit);
        }

        plugin.logAudit(
                player.uuid,
                player.username,
                player.ip,
                "ACCOUNT_AUTHORIZED",
                "Authorized by " + sender.getName());

        sender.sendMessage(plugin.color(
                "&aAuthorized &f" + player.username
                + " &afor owner &f" + owner.username + "&a."));
    }

    private void removeUser(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 2) {
            usage(sender, "/ta removeuser <player>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cYou cannot remove a Main Account."));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {
            db.setAutoCommit(false);

            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM authorized_accounts
                    WHERE authorized_uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts SET approved = 0 WHERE uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'DENIED'
                    WHERE uuid = ?
                    """)) {
                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            db.commit();
        } catch (SQLException ex) {
            rollback(db, ex);
            throw ex;
        } finally {
            db.setAutoCommit(oldAutoCommit);
        }

        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                "AUTHORIZATION_REMOVED",
                "Removed by " + sender.getName());

        sender.sendMessage(plugin.color(
                "&aRemoved authorization for &f" + account.username + "&a."));
    }

    private void limit(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {
        if (args.length != 3) {
            usage(sender, "/ta limit <player> <number>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (account.ip == null || account.ip.isBlank()) {
            sender.sendMessage(plugin.color(
                    "&cPlayer has no stored IP address."));
            return;
        }

        int amount;

        try {
            amount = Integer.parseInt(args[2]);
        } catch (NumberFormatException ex) {
            plugin.sendMessage(sender, "invalid-number");
            return;
        }

        if (amount < 1) {
            plugin.sendMessage(sender, "invalid-number");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO ip_limits
                    (ip_address, max_accounts, updated_by, updated_at)
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

        sender.sendMessage(plugin.color(
                "&aIP account limit set to &f" + amount
                + " &afor &f" + account.username + "&a."));
    }

    private void authorize(
            Connection db,
            String ownerUuid,
            String playerUuid
    ) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO authorized_accounts
                    (owner_uuid, authorized_uuid, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(authorized_uuid) DO UPDATE SET
                    owner_uuid = excluded.owner_uuid,
                    created_at = excluded.created_at
                """)) {
            ps.setString(1, ownerUuid);
            ps.setString(2, playerUuid);
            ps.setString(3, Instant.now().toString());
            ps.executeUpdate();
        }
    }

    private Account findAccount(Connection db, String username)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address, approved, created_at, last_seen
                FROM accounts
                WHERE lower(username) = lower(?)
                ORDER BY last_seen DESC
                LIMIT 1
                """)) {
            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

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

    private boolean accountExists(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT 1 FROM accounts WHERE uuid = ? LIMIT 1")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isMain(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1 FROM ip_main_accounts
                WHERE main_uuid = ?
                LIMIT 1
                """)) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isAuthorized(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1 FROM authorized_accounts
                WHERE authorized_uuid = ?
                LIMIT 1
                """)) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "Unknown";
        }

        if (ip.contains(":")) {
            int separator = ip.lastIndexOf(':');
            return separator > 0
                    ? ip.substring(0, separator) + ":****"
                    : "****";
        }

        String[] parts = ip.split("\\.", -1);

        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + ".***.***";
        }

        return "****";
    }

    private void rollback(Connection db, SQLException original) {
        try {
            db.rollback();
        } catch (SQLException rollbackError) {
            original.addSuppressed(rollbackError);
        }
    }

    private void usage(CommandSender sender, String message) {
        sender.sendMessage(plugin.color("&eUsage: " + message));
    }

    private static final class Account {
        final String uuid;
        final String username;
        final String ip;
        final int approved;
        final String created;
        final String lastSeen;

        Account(
                String uuid,
                String username,
                String ip,
                int approved,
                String created,
                String lastSeen
        ) {
            this.uuid = uuid;
            this.username = username;
            this.ip = ip;
            this.approved = approved;
            this.created = created;
            this.lastSeen = lastSeen;
        }
    }
}

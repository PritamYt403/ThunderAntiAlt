
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

        if (!sender.hasPermission("thunderantialt.admin")) {
            plugin.sendMessage(sender, "no-permission");
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

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
                    case "ban" -> ban(sender, db, args);
                    case "unban" -> unban(sender, db, args);
                    case "limit" -> limit(sender, db, args);

                    default -> plugin.sendMessage(
                            sender,
                            "unknown-command"
                    );
                }

            } catch (SQLException ex) {

                plugin.getLogger().severe(
                        "Admin command database error: "
                                + ex.getMessage()
                );

                plugin.sendMessage(sender, "database-error");
            }
        }

        return true;
    }

    private void sendHelp(CommandSender sender) {

        sender.sendMessage(plugin.color("&6--- ThunderAntiAlt Commands ---"));
        sender.sendMessage(plugin.color("&e/ta pending"));
        sender.sendMessage(plugin.color("&e/ta approve <player-or-uuid>"));
        sender.sendMessage(plugin.color("&e/ta deny <player-or-uuid>"));
        sender.sendMessage(plugin.color("&e/ta info <player-or-uuid>"));
        sender.sendMessage(plugin.color("&e/ta adduser <alt> <main>"));
        sender.sendMessage(plugin.color("&e/ta removeuser <alt>"));
        sender.sendMessage(plugin.color("&e/ta ban <player-or-uuid> [reason]"));
        sender.sendMessage(plugin.color("&e/ta unban <player-or-uuid>"));
        sender.sendMessage(plugin.color("&e/ta limit <player> <number>"));
        sender.sendMessage(plugin.color("&e/ta reload"));
    }

    private void pending(
            CommandSender sender,
            Connection db
    ) throws SQLException {

        sender.sendMessage(plugin.color("&6--- Pending Alt Accounts ---"));

        int count = 0;

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT username, uuid, main_uuid, attempts
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
                        + " &7| Attempts: &f" + rs.getInt("attempts")
                ));
            }
        }

        sender.sendMessage(plugin.color(
                count == 0
                        ? "&aNo pending accounts."
                        : "&ePending accounts: &f" + count
        ));
    }

    private void approve(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta approve <player-or-uuid>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot be approved as an Alt."
            ));
            return;
        }

        if (isBanned(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cThis account is banned. Unban it first."
            ));
            return;
        }

        String mainUuid;
        String pendingStatus;

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT main_uuid, status
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, account.uuid);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    sender.sendMessage(plugin.color(
                            "&cNo pending request exists for this account."
                    ));
                    return;
                }

                mainUuid = rs.getString("main_uuid");
                pendingStatus = rs.getString("status");
            }
        }

        if (!"PENDING".equalsIgnoreCase(pendingStatus)) {
            sender.sendMessage(plugin.color(
                    "&cThis request is not pending. Status: "
                            + pendingStatus
            ));
            return;
        }

        if (mainUuid == null
                || mainUuid.isBlank()
                || "UNKNOWN".equalsIgnoreCase(mainUuid)
                || mainUuid.equalsIgnoreCase(account.uuid)) {

            sender.sendMessage(plugin.color(
                    "&cInvalid Main Account relationship."
            ));
            return;
        }

        if (!isMain(db, mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cThe linked Main Account does not exist."
            ));
            return;
        }

        if (isBanned(db, mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cThe Main Account is banned."
            ));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {

            db.setAutoCommit(false);

            // An Alt UUID can belong to only one Main UUID.
            String existingOwner = getAuthorizedOwner(
                    db,
                    account.uuid
            );

            if (existingOwner != null
                    && !existingOwner.equalsIgnoreCase(mainUuid)) {

                throw new SQLException(
                        "This Alt is already linked to another Main Account."
                );
            }

            authorize(db, mainUuid, account.uuid);

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'APPROVED',
                        last_seen = ?
                    WHERE uuid = ?
                      AND status = 'PENDING'
                    """)) {

                ps.setString(1, Instant.now().toString());
                ps.setString(2, account.uuid);

                if (ps.executeUpdate() != 1) {
                    throw new SQLException(
                            "Pending request changed during approval."
                    );
                }
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 1,
                        last_seen = ?
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
                "Approved for Main UUID " + mainUuid
                        + " by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aApproved Alt: &f" + account.username
                        + " &7(Main: " + mainUuid + ")"
        ));
    }

    private void deny(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta deny <player-or-uuid>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot be denied as an Alt."
            ));
            return;
        }

        boolean oldAutoCommit = db.getAutoCommit();

        try {

            db.setAutoCommit(false);

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'DENIED',
                        last_seen = ?
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, Instant.now().toString());
                ps.setString(2, account.uuid);
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
                    UPDATE accounts
                    SET approved = 0
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
                "ACCOUNT_DENIED",
                "Denied by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&cDenied Alt Account: &f" + account.username
        ));
    }

    private void addUser(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 3) {
            usage(sender, "/ta adduser <alt> <main>");
            return;
        }

        Account alt = findAccount(db, args[1]);
        Account main = findAccount(db, args[2]);

        if (alt == null || main == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (alt.uuid.equalsIgnoreCase(main.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA player cannot be their own Alt."
            ));
            return;
        }

        if (isMain(db, alt.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot become an Alt."
            ));
            return;
        }

        if (!isMain(db, main.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cOwner must be a registered Main Account."
            ));
            return;
        }

        if (isBanned(db, alt.uuid) || isBanned(db, main.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cMain or Alt account is banned."
            ));
            return;
        }

        // adduser is deliberately not an approval bypass.
        // It can only confirm an already pending relationship.
        String pendingMain = getPendingMain(db, alt.uuid);

        if (pendingMain == null
                || !pendingMain.equalsIgnoreCase(main.uuid)) {

            sender.sendMessage(plugin.color(
                    "&cNo matching pending request exists."
                            + " Use the normal approval process."
            ));
            return;
        }

        sender.sendMessage(plugin.color(
                "&eThis account is pending. Use &f/ta approve "
                        + alt.username
                        + " &eafter checking the request."
        ));
    }

    private void removeUser(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta removeuser <alt>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, account.uuid)) {
            sender.sendMessage(plugin.color(
                    "&cYou cannot remove a Main Account."
            ));
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
                    UPDATE accounts
                    SET approved = 0
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, account.uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'DENIED',
                        last_seen = ?
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
                "AUTHORIZATION_REMOVED",
                "Removed by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aAlt authorization removed: &f" + account.username
        ));
    }

    private void ban(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length < 2) {
            usage(sender, "/ta ban <player-or-uuid> [reason]");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String reason = args.length >= 3
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length))
                : "Banned by administrator";

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO account_bans
                    (player_uuid, username, reason, banned_by, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(player_uuid) DO UPDATE SET
                    username = excluded.username,
                    reason = excluded.reason,
                    banned_by = excluded.banned_by,
                    created_at = excluded.created_at
                """)) {

            ps.setString(1, account.uuid);
            ps.setString(2, account.username);
            ps.setString(3, reason);
            ps.setString(4, sender.getName());
            ps.setString(5, Instant.now().toString());

            ps.executeUpdate();
        }

        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                "ACCOUNT_BANNED",
                reason + " | By " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&cBanned: &f" + account.username
                        + " &7Reason: " + reason
        ));

        // The login listener must also check whether this UUID
        // is the owner of an authorized Alt.
        sender.sendMessage(plugin.color(
                "&eLinked Alt blocking is enforced by AccountListener."
        ));
    }

    private void unban(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta unban <player-or-uuid>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        try (PreparedStatement ps = db.prepareStatement("""
                DELETE FROM account_bans
                WHERE player_uuid = ?
                """)) {

            ps.setString(1, account.uuid);

            if (ps.executeUpdate() == 0) {
                sender.sendMessage(plugin.color(
                        "&eThis account is not banned."
                ));
                return;
            }
        }

        plugin.logAudit(
                account.uuid,
                account.username,
                account.ip,
                "ACCOUNT_UNBANNED",
                "Unbanned by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aUnbanned: &f" + account.username
        ));
    }

    private void info(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta info <player-or-uuid>");
            return;
        }

        Account account = findAccount(db, args[1]);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String status = "PENDING";
        String mainUuid = "-";

        if (isMain(db, account.uuid)) {

            status = "MAIN";
            mainUuid = account.uuid;

        } else {

            String owner = getAuthorizedOwner(db, account.uuid);

            if (owner != null) {
                status = "APPROVED";
                mainUuid = owner;
            } else {

                String pendingMain = getPendingMain(db, account.uuid);

                if (pendingMain != null) {
                    mainUuid = pendingMain;
                }

                String pendingStatus = getPendingStatus(db, account.uuid);

                if (pendingStatus != null) {
                    status = pendingStatus;
                }
            }
        }

        if (isBanned(db, account.uuid)) {
            status = "BANNED";
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
                    "&cPlayer has no stored IP address."
            ));
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
                "&aLegacy IP limit updated to &f" + amount
        ));
    }

    private Account findAccount(
            Connection db,
            String identifier
    ) throws SQLException {

        // UUID lookup is exact and unambiguous.
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address, approved,
                       created_at, last_seen
                FROM accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, identifier);

            try (ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {
                    return readAccount(rs);
                }
            }
        }

        // Username lookup is accepted only if unique.
        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address, approved,
                       created_at, last_seen
                FROM accounts
                WHERE username = ? COLLATE NOCASE
                LIMIT 2
                """)) {

            ps.setString(1, identifier);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                Account account = readAccount(rs);

                if (rs.next()) {
                    throw new SQLException(
                            "Username is ambiguous. Use the exact UUID."
                    );
                }

                return account;
            }
        }
    }

    private Account readAccount(ResultSet rs)
            throws SQLException {

        return new Account(
                rs.getString("uuid"),
                rs.getString("username"),
                rs.getString("ip_address"),
                rs.getInt("approved"),
                rs.getString("created_at"),
                rs.getString("last_seen")
        );
    }

    private boolean isMain(
            Connection db,
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1
                FROM main_accounts
                WHERE main_uuid = ?
                LIMIT 1
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isBanned(
            Connection db,
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1
                FROM account_bans
                WHERE player_uuid = ?
                LIMIT 1
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private String getAuthorizedOwner(
            Connection db,
            String altUuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT owner_uuid
                FROM authorized_accounts
                WHERE authorized_uuid = ?
                """)) {

            ps.setString(1, altUuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("owner_uuid") : null;
            }
        }
    }

    private String getPendingMain(
            Connection db,
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT main_uuid
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("main_uuid") : null;
            }
        }
    }

    private String getPendingStatus(
            Connection db,
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT status
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("status") : null;
            }
        }
    }

    private void authorize(
            Connection db,
            String mainUuid,
            String altUuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO authorized_accounts
                    (owner_uuid, authorized_uuid, created_at)
                VALUES (?, ?, ?)
                """)) {

            ps.setString(1, mainUuid);
            ps.setString(2, altUuid);
            ps.setString(3, Instant.now().toString());

            ps.executeUpdate();
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

    private void rollback(
            Connection db,
            SQLException original
    ) {

        try {
            db.rollback();
        } catch (SQLException rollbackError) {
            original.addSuppressed(rollbackError);
        }
    }

    private void usage(
            CommandSender sender,
            String message
    ) {

        sender.sendMessage(
                plugin.color("&eUsage: " + message)
        );
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

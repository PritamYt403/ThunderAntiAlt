
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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
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

            if (db == null || isClosed(db)) {
                plugin.sendMessage(sender, "database-error");
                return true;
            }

            try {
                switch (sub) {
                    case "setmain" -> setMain(sender, db, args);
                    case "pending" -> pending(sender, db);
                    case "approve" -> approve(sender, db, args);
                    case "deny" -> deny(sender, db, args);
                    case "info" -> info(sender, db, args);
                    case "removeuser" -> removeUser(sender, db, args);
                    case "ban" -> ban(sender, db, args);
                    case "unban" -> unban(sender, db, args);

                    default -> plugin.sendMessage(
                            sender,
                            "unknown-command"
                    );
                }

            } catch (SQLException ex) {

                plugin.getLogger().log(
                        Level.SEVERE,
                        "Admin command database error.",
                        ex
                );

                plugin.sendMessage(sender, "database-error");
            }
        }

        return true;
    }

    private boolean isClosed(Connection db) {
        try {
            return db.isClosed();
        } catch (SQLException ex) {
            return true;
        }
    }

    private void sendHelp(CommandSender sender) {

        sender.sendMessage(plugin.color("&6--- ThunderAntiAlt Commands ---"));
        sender.sendMessage(plugin.color("&e/ta setmain <uuid> <username>"));
        sender.sendMessage(plugin.color("&e/ta pending"));
        sender.sendMessage(plugin.color("&e/ta approve <alt-uuid> <main-uuid>"));
        sender.sendMessage(plugin.color("&e/ta deny <alt-uuid>"));
        sender.sendMessage(plugin.color("&e/ta info <uuid>"));
        sender.sendMessage(plugin.color("&e/ta removeuser <alt-uuid>"));
        sender.sendMessage(plugin.color("&e/ta ban <uuid> [reason]"));
        sender.sendMessage(plugin.color("&e/ta unban <uuid>"));
        sender.sendMessage(plugin.color("&e/ta reload"));
    }

    // --------------------------------------------------
    // TRANSACTION HELPER
    // --------------------------------------------------

    @FunctionalInterface
    private interface SqlTransaction {
        void execute() throws SQLException;
    }

    /**
     * Executes database operations atomically.
     * Preserves the original failure if rollback or
     * auto-commit restoration also fails.
     */
    private void executeTransaction(
            Connection db,
            SqlTransaction transaction
    ) throws SQLException {

        boolean oldAutoCommit = db.getAutoCommit();
        Throwable originalFailure = null;

        try {
            db.setAutoCommit(false);

            transaction.execute();

            db.commit();

        } catch (SQLException | RuntimeException | Error ex) {

            originalFailure = ex;

            try {
                db.rollback();
            } catch (SQLException rollbackError) {
                ex.addSuppressed(rollbackError);
            }

            throw ex;

        } finally {

            try {
                db.setAutoCommit(oldAutoCommit);

            } catch (SQLException restoreError) {

                if (originalFailure != null) {
                    originalFailure.addSuppressed(restoreError);
                } else {
                    throw restoreError;
                }
            }
        }
    }

    // --------------------------------------------------
    // MAIN ACCOUNT REGISTRATION
    // --------------------------------------------------

    private void setMain(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 3) {
            usage(sender, "/ta setmain <uuid> <username>");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        String username = args[2];

        if (username.length() > 16
                || !username.matches("[A-Za-z0-9_]+")) {
            sender.sendMessage(plugin.color("&cInvalid Minecraft username."));
            return;
        }

        if (isMain(db, uuid)) {
            sender.sendMessage(plugin.color(
                    "&eThis UUID is already a Main Account."
            ));
            return;
        }

        if (getAuthorizedOwner(db, uuid) != null) {
            sender.sendMessage(plugin.color(
                    "&cThis UUID is already registered as an Alt."
            ));
            return;
        }

        if (isBanned(db, uuid)) {
            sender.sendMessage(plugin.color(
                    "&cThis UUID is banned. Unban it first."
            ));
            return;
        }

        String now = Instant.now().toString();

        executeTransaction(db, () -> {

            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT INTO main_accounts
                        (main_uuid, username, created_at, last_seen)
                    VALUES (?, ?, ?, ?)
                    """)) {

                ps.setString(1, uuid);
                ps.setString(2, username);
                ps.setString(3, now);
                ps.setString(4, now);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    INSERT INTO accounts
                        (uuid, username, ip_address, account_limit,
                         approved, created_at, last_seen)
                    VALUES (?, ?, NULL, 1, 1, ?, ?)
                    ON CONFLICT(uuid) DO UPDATE SET
                        username = excluded.username,
                        approved = 1,
                        last_seen = excluded.last_seen
                    """)) {

                ps.setString(1, uuid);
                ps.setString(2, username);
                ps.setString(3, now);
                ps.setString(4, now);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM pending_alt_accounts
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, uuid);
                ps.executeUpdate();
            }
        });

        plugin.logAudit(
                uuid,
                username,
                null,
                "MAIN_ACCOUNT_CREATED",
                "Created by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aMain Account registered successfully."
        ));
        sender.sendMessage(plugin.color("&eUsername: &f" + username));
        sender.sendMessage(plugin.color("&eUUID: &f" + uuid));
    }

    // --------------------------------------------------
    // PENDING ACCOUNTS
    // --------------------------------------------------

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

    // --------------------------------------------------
    // APPROVE ALT
    // --------------------------------------------------

    private void approve(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 3) {
            usage(sender, "/ta approve <alt-uuid> <main-uuid>");
            return;
        }

        String altUuid = normalizeUuid(args[1]);
        String mainUuid = normalizeUuid(args[2]);

        if (altUuid == null || mainUuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        if (altUuid.equals(mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cMain and Alt UUID cannot be identical."
            ));
            return;
        }

        Account alt = findAccount(db, altUuid);

        if (alt == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, altUuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot be approved as an Alt."
            ));
            return;
        }

        if (!isMain(db, mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cThis Main UUID is not registered."
            ));
            return;
        }

        if (isBanned(db, altUuid) || isBanned(db, mainUuid)) {
            sender.sendMessage(plugin.color(
                    "&cThe Main or Alt account is banned."
            ));
            return;
        }

        String status;
        String oldMain;

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT status, main_uuid
                FROM pending_alt_accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, altUuid);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    sender.sendMessage(plugin.color(
                            "&cNo pending request exists for this UUID."
                    ));
                    return;
                }

                status = rs.getString("status");
                oldMain = rs.getString("main_uuid");
            }
        }

        if (!"PENDING".equalsIgnoreCase(status)) {
            sender.sendMessage(plugin.color(
                    "&cThis account is not pending. Status: " + status
            ));
            return;
        }

        if (oldMain != null
                && !"UNKNOWN".equalsIgnoreCase(oldMain)
                && !oldMain.equalsIgnoreCase(mainUuid)) {

            sender.sendMessage(plugin.color(
                    "&cThis request is already assigned to another Main."
            ));
            return;
        }

        String existingOwner = getAuthorizedOwner(db, altUuid);

        if (existingOwner != null
                && !existingOwner.equalsIgnoreCase(mainUuid)) {

            sender.sendMessage(plugin.color(
                    "&cThis Alt is already linked to another Main."
            ));
            return;
        }

        String now = Instant.now().toString();

        executeTransaction(db, () -> {

            if (existingOwner == null) {
                try (PreparedStatement ps = db.prepareStatement("""
                        INSERT INTO authorized_accounts
                            (owner_uuid, authorized_uuid, created_at)
                        VALUES (?, ?, ?)
                        """)) {

                    ps.setString(1, mainUuid);
                    ps.setString(2, altUuid);
                    ps.setString(3, now);
                    ps.executeUpdate();
                }
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET main_uuid = ?,
                        status = 'APPROVED',
                        last_seen = ?
                    WHERE uuid = ?
                      AND status = 'PENDING'
                    """)) {

                ps.setString(1, mainUuid);
                ps.setString(2, now);
                ps.setString(3, altUuid);

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

                ps.setString(1, now);
                ps.setString(2, altUuid);
                ps.executeUpdate();
            }
        });

        plugin.logAudit(
                altUuid,
                alt.username,
                alt.ip,
                "ACCOUNT_APPROVED",
                "Linked to Main UUID " + mainUuid
                        + " by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aAlt approved successfully: &f" + alt.username
        ));
        sender.sendMessage(plugin.color(
                "&eLinked Main UUID: &f" + mainUuid
        ));
    }

    // --------------------------------------------------
    // DENY ALT
    // --------------------------------------------------

    private void deny(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta deny <alt-uuid>");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        Account account = findAccount(db, uuid);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, uuid)) {
            sender.sendMessage(plugin.color(
                    "&cA Main Account cannot be denied as an Alt."
            ));
            return;
        }

        String status = getPendingStatus(db, uuid);

        if (!"PENDING".equalsIgnoreCase(status)) {
            plugin.sendMessage(sender, "account-not-pending");
            return;
        }

        executeTransaction(db, () -> {

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'DENIED',
                        last_seen = ?
                    WHERE uuid = ?
                      AND status = 'PENDING'
                    """)) {

                ps.setString(1, Instant.now().toString());
                ps.setString(2, uuid);

                if (ps.executeUpdate() != 1) {
                    throw new SQLException(
                            "Pending account changed during denial."
                    );
                }
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 0
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, uuid);
                ps.executeUpdate();
            }
        });

        plugin.logAudit(
                uuid,
                account.username,
                account.ip,
                "ACCOUNT_DENIED",
                "Denied by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&cAlt account denied: &f" + account.username
        ));
    }

    // --------------------------------------------------
    // REMOVE ALT AUTHORIZATION
    // --------------------------------------------------

    private void removeUser(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta removeuser <alt-uuid>");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        Account account = findAccount(db, uuid);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        if (isMain(db, uuid)) {
            sender.sendMessage(plugin.color(
                    "&cYou cannot remove a Main Account as an Alt."
            ));
            return;
        }

        executeTransaction(db, () -> {

            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM authorized_accounts
                    WHERE authorized_uuid = ?
                    """)) {

                ps.setString(1, uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE accounts
                    SET approved = 0
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, uuid);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = db.prepareStatement("""
                    UPDATE pending_alt_accounts
                    SET status = 'DENIED',
                        last_seen = ?
                    WHERE uuid = ?
                    """)) {

                ps.setString(1, Instant.now().toString());
                ps.setString(2, uuid);
                ps.executeUpdate();
            }
        });

        Player onlinePlayer = Bukkit.getPlayer(UUID.fromString(uuid));

        if (onlinePlayer != null && onlinePlayer.isOnline()) {
            onlinePlayer.kickPlayer(plugin.color(
                    "&cYour Alt authorization has been revoked."
            ));
        }

        plugin.logAudit(
                uuid,
                account.username,
                account.ip,
                "AUTHORIZATION_REMOVED",
                "Removed by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aAlt authorization removed: &f" + account.username
        ));
    }

    // --------------------------------------------------
    // BAN
    // --------------------------------------------------

    private void ban(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length < 2) {
            usage(sender, "/ta ban <uuid> [reason]");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        Account account = findAccount(db, uuid);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String reason = args.length > 2
                ? String.join(" ", Arrays.copyOfRange(args, 2, args.length))
                : "Banned by administrator";

        executeTransaction(db, () -> {

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

                ps.setString(1, uuid);
                ps.setString(2, account.username);
                ps.setString(3, reason);
                ps.setString(4, sender.getName());
                ps.setString(5, Instant.now().toString());
                ps.executeUpdate();
            }
        });

        plugin.logAudit(
                uuid,
                account.username,
                account.ip,
                "ACCOUNT_BANNED",
                reason + " | By " + sender.getName()
        );

        List<String> affectedUuids = new ArrayList<>();
        affectedUuids.add(uuid);

        if (isMain(db, uuid)) {

            try (PreparedStatement ps = db.prepareStatement("""
                    SELECT authorized_uuid
                    FROM authorized_accounts
                    WHERE owner_uuid = ?
                    """)) {

                ps.setString(1, uuid);

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String altUuid = rs.getString("authorized_uuid");

                        if (altUuid != null) {
                            affectedUuids.add(altUuid);
                        }
                    }
                }
            }
        }

        String kickMessage = plugin.color(
                "&cThis account or its Main Account has been banned."
        );

        int kicked = 0;

        for (String affectedUuid : affectedUuids) {

            try {
                Player onlinePlayer = Bukkit.getPlayer(
                        UUID.fromString(affectedUuid)
                );

                if (onlinePlayer != null && onlinePlayer.isOnline()) {
                    onlinePlayer.kickPlayer(kickMessage);
                    kicked++;
                }

            } catch (IllegalArgumentException ex) {
                plugin.getLogger().warning(
                        "Invalid UUID in account authorization data: "
                                + affectedUuid
                );
            }
        }

        sender.sendMessage(plugin.color(
                "&cBanned: &f" + account.username
        ));

        sender.sendMessage(plugin.color(
                "&eOnline affected accounts kicked: &f" + kicked
        ));
    }

    // --------------------------------------------------
    // UNBAN
    // --------------------------------------------------

    private void unban(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta unban <uuid>");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        Account account = findAccount(db, uuid);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        int[] deletedRows = {0};

        executeTransaction(db, () -> {

            try (PreparedStatement ps = db.prepareStatement("""
                    DELETE FROM account_bans
                    WHERE player_uuid = ?
                    """)) {

                ps.setString(1, uuid);
                deletedRows[0] = ps.executeUpdate();
            }
        });

        if (deletedRows[0] == 0) {
            sender.sendMessage(plugin.color(
                    "&eThis account is not banned."
            ));
            return;
        }

        plugin.logAudit(
                uuid,
                account.username,
                account.ip,
                "ACCOUNT_UNBANNED",
                "Unbanned by " + sender.getName()
        );

        sender.sendMessage(plugin.color(
                "&aUnbanned: &f" + account.username
        ));
    }

    // --------------------------------------------------
    // ACCOUNT INFO
    // --------------------------------------------------

    private void info(
            CommandSender sender,
            Connection db,
            String[] args
    ) throws SQLException {

        if (args.length != 2) {
            usage(sender, "/ta info <uuid>");
            return;
        }

        String uuid = normalizeUuid(args[1]);

        if (uuid == null) {
            sender.sendMessage(plugin.color("&cInvalid UUID."));
            return;
        }

        Account account = findAccount(db, uuid);

        if (account == null) {
            plugin.sendMessage(sender, "player-not-found");
            return;
        }

        String status = "UNREGISTERED";
        String mainUuid = "-";
        boolean inheritedBan = false;

        if (isMain(db, uuid)) {

            status = "MAIN";
            mainUuid = uuid;

        } else {

            String owner = getAuthorizedOwner(db, uuid);

            if (owner != null) {

                status = "APPROVED";
                mainUuid = owner;

                inheritedBan = isBanned(db, owner);

            } else {

                String pendingStatus = getPendingStatus(db, uuid);
                String pendingMain = getPendingMain(db, uuid);

                if (pendingStatus != null) {
                    status = pendingStatus;
                }

                if (pendingMain != null) {
                    mainUuid = pendingMain;
                }
            }
        }

        if (isBanned(db, uuid) || inheritedBan) {
            status = "BANNED";
        }

        sender.sendMessage(plugin.color("&6--- Account Info ---"));
        sender.sendMessage(plugin.color("&eUsername: &f" + account.username));
        sender.sendMessage(plugin.color("&eUUID: &f" + uuid));
        sender.sendMessage(plugin.color("&eStatus: &f" + status));
        sender.sendMessage(plugin.color("&eMain UUID: &f" + mainUuid));
        sender.sendMessage(plugin.color("&eCreated: &f" + account.created));
        sender.sendMessage(plugin.color("&eLast Seen: &f" + account.lastSeen));
    }

    // --------------------------------------------------
    // DATABASE HELPERS
    // --------------------------------------------------

    private Account findAccount(
            Connection db,
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT uuid, username, ip_address,
                       created_at, last_seen
                FROM accounts
                WHERE uuid = ?
                """)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new Account(
                            rs.getString("uuid"),
                            rs.getString("username"),
                            rs.getString("ip_address"),
                            rs.getString("created_at"),
                            rs.getString("last_seen")
                    );
                }
            }
        }

        return null;
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
            String uuid
    ) throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT owner_uuid
                FROM authorized_accounts
                WHERE authorized_uuid = ?
                LIMIT 1
                """)) {

            ps.setString(1, uuid);

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

    private String normalizeUuid(String value) {

        if (value == null) {
            return null;
        }

        try {
            UUID uuid = UUID.fromString(value);

            if (!uuid.toString().equalsIgnoreCase(value)) {
                return null;
            }

            return uuid.toString();

        } catch (IllegalArgumentException ex) {
            return null;
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
        final String created;
        final String lastSeen;

        Account(
                String uuid,
                String username,
                String ip,
                String created,
                String lastSeen
        ) {
            this.uuid = uuid;
            this.username = username;
            this.ip = ip;
            this.created = created;
            this.lastSeen = lastSeen;
        }
    }
}

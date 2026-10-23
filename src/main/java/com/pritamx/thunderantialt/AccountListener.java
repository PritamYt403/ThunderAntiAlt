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
import java.util.Locale;
import java.util.logging.Level;

public final class AccountListener implements Listener {

    private final ThunderAntiAlt plugin;

    public AccountListener(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        Player player = event.getPlayer();
        String uuid = player.getUniqueId().toString();
        String username = player.getName();

        InetAddress address = event.getAddress();
        String ip = address == null ? null : address.getHostAddress();

        if (player.isOp()
                || player.hasPermission("thunderantialt.bypass")) {
            return;
        }

        if (ip == null || ip.isBlank()) {
            deny(event, "database-error");
            return;
        }

        synchronized (plugin.getDatabaseLock()) {
            Connection db = plugin.getDatabaseConnection();

            if (db == null) {
                handleDatabaseFailure(event);
                return;
            }

            boolean oldAutoCommit = true;
            boolean transactionStarted = false;

            try {
                oldAutoCommit = db.getAutoCommit();
                db.setAutoCommit(false);
                transactionStarted = true;

                if (isBanned(db, uuid)) {
                    db.commit();
                    transactionStarted = false;

                    deny(event, "account-banned");
                    audit(uuid, username, ip, "LOGIN_BLOCKED",
                            "Account is banned");
                    return;
                }

                AccountRecord account = getAccount(db, uuid);
                PendingRecord pending = getPending(db, uuid);

                // Main accounts may reconnect from another IP.
                if (isMainUuid(db, uuid)) {
                    ensureAccount(db, uuid, username, ip, true);
                    saveMainAccount(db, ip, uuid, username);

                    db.commit();
                    transactionStarted = false;

                    audit(uuid, username, ip, "MAIN_LOGIN",
                            "Main account login");
                    return;
                }

                // Explicitly authorized accounts.
                if (isAuthorizedAlt(db, uuid)) {
                    if (account != null
                            && plugin.getConfig().getBoolean(
                                    "settings.require-new-ip-approval", true)
                            && account.ipAddress != null
                            && !account.ipAddress.equals(ip)) {

                        String mainUuid = findMainForAccount(db, uuid);

                        if (mainUuid == null || mainUuid.isBlank()) {
                            mainUuid = "UNKNOWN";
                        }

                        markPending(db, uuid, username, ip, mainUuid);
                        db.commit();
                        transactionStarted = false;

                        deny(event, "approval-required");
                        audit(uuid, username, ip, "LOGIN_BLOCKED",
                                "Authorized account attempted login from a new IP");
                        alertAdmins(username,
                                "New IP requires approval");
                        return;
                    }

                    registerAuthorizedAccount(db, uuid, username, ip);

                    db.commit();
                    transactionStarted = false;

                    audit(uuid, username, ip, "AUTHORIZED_LOGIN",
                            "Authorized account login");
                    return;
                }

                // Denied and pending accounts must be reviewed by an admin.
                if (pending != null) {
                    updatePendingAttempt(db, uuid, username, ip);

                    db.commit();
                    transactionStarted = false;

                    if ("DENIED".equals(pending.status)) {
                        deny(event, "account-denied-login");
                    } else {
                        deny(event, "approval-required");
                    }

                    audit(uuid, username, ip, "LOGIN_BLOCKED",
                            "Account status: " + pending.status);
                    alertAdmins(username,
                            "Account requires admin review");
                    return;
                }

                String mainUuid = findMainUuid(db, ip, uuid);

                if (mainUuid == null && account != null) {
                    mainUuid = findMainForAccount(db, uuid);
                }

                // Register the first account seen on this IP.
                if (mainUuid == null && account == null) {
                    int configuredLimit = Math.max(1,
                            plugin.getConfig().getInt(
                                    "settings.max-accounts-per-ip", 1));

                    int ipLimit = getIpLimit(db, ip, configuredLimit);
                    int count = countAccountsOnIp(db, ip);

                    if (count >= Math.min(configuredLimit, ipLimit)) {
                        db.rollback();
                        transactionStarted = false;

                        deny(event, "account-limit");
                        audit(uuid, username, ip, "LOGIN_BLOCKED",
                                "IP account limit reached");
                        alertAdmins(username,
                                "IP account limit reached");
                        return;
                    }

                    insertAccount(db, uuid, username, ip, true);
                    saveMainAccount(db, ip, uuid, username);

                    db.commit();
                    transactionStarted = false;

                    audit(uuid, username, ip,
                            "MAIN_ACCOUNT_REGISTERED",
                            "First account registered for IP");
                    return;
                }

                if (mainUuid == null || mainUuid.isBlank()) {
                    mainUuid = "UNKNOWN";
                }

                if (account == null) {
                    insertAccount(db, uuid, username, ip, false);
                } else {
                    updateBinding(db, uuid, username, ip, false);
                }

                markPending(db, uuid, username, ip, mainUuid);

                db.commit();
                transactionStarted = false;

                deny(event, "approval-required");
                audit(uuid, username, ip, "ALT_PENDING",
                        "Waiting for approval; main UUID: " + mainUuid);
                alertAdmins(username,
                        "New alt account pending approval");

            } catch (SQLException ex) {
                if (transactionStarted) {
                    try {
                        db.rollback();
                    } catch (SQLException rollbackError) {
                        ex.addSuppressed(rollbackError);
                    }
                }

                plugin.getLogger().log(Level.SEVERE,
                        "Account verification failed for " + username, ex);

                handleDatabaseFailure(event);

            } finally {
                try {
                    if (db.getAutoCommit() != oldAutoCommit) {
                        db.setAutoCommit(oldAutoCommit);
                    }
                } catch (SQLException ex) {
                    plugin.getLogger().log(Level.SEVERE,
                            "Could not restore database transaction state", ex);

                    // Only enforce fail-closed if login has not already
                    // been denied by another check.
                    if (event.getResult() == PlayerLoginEvent.Result.ALLOWED) {
                        handleDatabaseFailure(event);
                    }
                }
            }
        }
    }

    private boolean isBanned(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT 1 FROM account_bans WHERE player_uuid = ? LIMIT 1")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isMainUuid(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT 1 FROM ip_main_accounts WHERE main_uuid = ? LIMIT 1")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isAuthorizedAlt(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT 1 FROM authorized_accounts WHERE authorized_uuid = ? LIMIT 1")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private String findMainUuid(Connection db, String ip, String excluded)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT main_uuid FROM ip_main_accounts WHERE ip_address = ? LIMIT 1")) {
            ps.setString(1, ip);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String value = rs.getString(1);

                    if (value != null && !value.equals(excluded)) {
                        return value;
                    }
                }
            }
        }

        try (PreparedStatement ps = db.prepareStatement(
                "SELECT uuid FROM accounts WHERE ip_address = ? AND approved = 1 LIMIT 1")) {
            ps.setString(1, ip);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String value = rs.getString(1);

                    if (value != null && !value.equals(excluded)) {
                        return value;
                    }
                }
            }
        }

        return null;
    }

    private String findMainForAccount(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT main_uuid FROM pending_alt_accounts WHERE uuid = ?")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        }

        try (PreparedStatement ps = db.prepareStatement(
                "SELECT owner_uuid FROM authorized_accounts WHERE authorized_uuid = ?")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        }

        return null;
    }

    private AccountRecord getAccount(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT ip_address FROM accounts WHERE uuid = ?")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next()
                        ? new AccountRecord(rs.getString(1)) : null;
            }
        }
    }

    private PendingRecord getPending(Connection db, String uuid)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT status FROM pending_alt_accounts WHERE uuid = ?")) {
            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next()
                        ? new PendingRecord(rs.getString(1)) : null;
            }
        }
    }

    private int getIpLimit(Connection db, String ip, int fallback)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT max_accounts FROM ip_limits WHERE ip_address = ?")) {
            ps.setString(1, ip);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next()
                        ? Math.max(1, rs.getInt(1)) : fallback;
            }
        }
    }

    private int countAccountsOnIp(Connection db, String ip)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT COUNT(*) FROM accounts WHERE ip_address = ?")) {
            ps.setString(1, ip);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    private void saveMainAccount(Connection db, String ip, String uuid,
                                 String username) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO ip_main_accounts
                    (ip_address, main_uuid, username, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    main_uuid = excluded.main_uuid,
                    username = excluded.username
                """)) {
            ps.setString(1, ip);
            ps.setString(2, uuid);
            ps.setString(3, username);
            ps.setString(4, Instant.now().toString());
            ps.executeUpdate();
        }
    }

    private void markPending(Connection db, String uuid, String username,
                             String ip, String mainUuid) throws SQLException {
        String now = Instant.now().toString();
        String owner = mainUuid == null || mainUuid.isBlank()
                ? "UNKNOWN" : mainUuid;

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO pending_alt_accounts
                    (uuid, username, ip_address, main_uuid,
                     first_seen, last_seen, attempts, status)
                VALUES (?, ?, ?, ?, ?, ?, 1, 'PENDING')
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    main_uuid = excluded.main_uuid,
                    last_seen = excluded.last_seen,
                    attempts = pending_alt_accounts.attempts + 1,
                    status = CASE
                        WHEN pending_alt_accounts.status = 'DENIED'
                        THEN 'DENIED'
                        ELSE 'PENDING'
                    END
                """)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, owner);
            ps.setString(5, now);
            ps.setString(6, now);
            ps.executeUpdate();
        }
    }

    private void updatePendingAttempt(Connection db, String uuid,
                                      String username, String ip)
            throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE pending_alt_accounts
                SET username = ?, ip_address = ?, last_seen = ?,
                    attempts = attempts + 1
                WHERE uuid = ?
                """)) {
            ps.setString(1, username);
            ps.setString(2, ip);
            ps.setString(3, Instant.now().toString());
            ps.setString(4, uuid);
            ps.executeUpdate();
        }
    }

    private void registerAuthorizedAccount(Connection db, String uuid,
                                            String username, String ip)
            throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, 1, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    ip_address = excluded.ip_address,
                    approved = 1,
                    last_seen = excluded.last_seen
                """)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, now);
            ps.setString(5, now);
            ps.executeUpdate();
        }
    }

    private void ensureAccount(Connection db, String uuid, String username,
                               String ip, boolean approved) throws SQLException {
        if (getAccount(db, uuid) == null) {
            insertAccount(db, uuid, username, ip, approved);
        } else {
            updateBinding(db, uuid, username, ip, approved);
        }
    }

    private void insertAccount(Connection db, String uuid, String username,
                               String ip, boolean approved) throws SQLException {
        String now = Instant.now().toString();

        try (PreparedStatement ps = db.prepareStatement("""
                INSERT INTO accounts
                    (uuid, username, ip_address, account_limit,
                     approved, created_at, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setInt(4, approved ? 1 : 0);
            ps.setString(5, now);
            ps.setString(6, now);
            ps.executeUpdate();
        }
    }

    private void updateBinding(Connection db, String uuid, String username,
                               String ip, boolean approved) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("""
                UPDATE accounts
                SET username = ?, ip_address = ?, approved = ?, last_seen = ?
                WHERE uuid = ?
                """)) {
            ps.setString(1, username);
            ps.setString(2, ip);
            ps.setInt(3, approved ? 1 : 0);
            ps.setString(4, Instant.now().toString());
            ps.setString(5, uuid);
            ps.executeUpdate();
        }
    }

    private void audit(String uuid, String username, String ip,
                       String action, String details) {
        boolean blocked = action.contains("BLOCKED")
                || action.equals("ALT_PENDING");

        if ((blocked && plugin.getConfig().getBoolean(
                "settings.log-blocked-attempts", true))
                || (!blocked && plugin.getConfig().getBoolean(
                "settings.log-successful-logins", true))) {
            plugin.logAudit(uuid, username, ip, action, details);
        }
    }

    private void deny(PlayerLoginEvent event, String key) {
        event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                plugin.getMessage(key));
    }

    private void handleDatabaseFailure(PlayerLoginEvent event) {
        if (plugin.getConfig().getBoolean(
                "security.fail-closed-on-database-error", true)) {
            deny(event, "database-error");
        } else {
            plugin.getLogger().warning(
                    "Database verification failed; login allowed because fail-closed is disabled.");
        }
    }

    private void alertAdmins(String username, String reason) {
        if (!plugin.getConfig().getBoolean("settings.alert-admins", true)) {
            return;
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player admin : Bukkit.getOnlinePlayers()) {
                if (admin.isOp()
                        || admin.hasPermission("thunderantialt.admin")) {
                    admin.sendMessage(plugin.getMessage("admin-blocked-login")
                            .replace("{player}", username)
                            .replace("{reason}", reason));
                }
            }
        });
    }

    private static final class AccountRecord {
        private final String ipAddress;

        private AccountRecord(String ipAddress) {
            this.ipAddress = ipAddress;
        }
    }

    private static final class PendingRecord {
        private final String status;

        private PendingRecord(String status) {
            this.status = status == null
                    ? "PENDING" : status.toUpperCase(Locale.ROOT);
        }
    }
}

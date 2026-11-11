
package com.pritamx.thunderantialt;

import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;

public final class AccountListener implements Listener {

    private final ThunderAntiAlt plugin;

    public AccountListener(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {

        String uuid = event.getPlayer().getUniqueId().toString();
        String username = event.getPlayer().getName();

        InetAddress address = event.getAddress();
        String ip = address == null ? null : address.getHostAddress();

        // OP and bypass permissions never skip account verification.
        synchronized (plugin.getDatabaseLock()) {

            Connection db = plugin.getDatabaseConnection();

            if (db == null) {
                deny(event, "database-error");
                return;
            }

            try {
                // 1. Check whether this UUID is banned.
                if (isBanned(db, uuid)) {
                    deny(event, "&cThis account is banned.");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED", "Account UUID is banned.");
                    return;
                }

                // 2. Check whether this UUID is a registered Main.
                boolean isMain = isMainAccount(db, uuid);

                // 3. Find the Main owner if this is an authorized Alt.
                String ownerUuid = getAuthorizedOwner(db, uuid);

                // A UUID must never be both Main and Alt.
                if (isMain && ownerUuid != null) {
                    deny(event, "database-error");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED",
                            "UUID has conflicting Main and Alt records.");
                    return;
                }

                // 4. Main Account verification.
                if (isMain) {

                    audit(uuid, username, ip,
                            "MAIN_LOGIN",
                            "Registered Main account.");

                    return;
                }

                // 5. Authorized Alt verification.
                if (ownerUuid != null) {

                    // Owner must still exist as a registered Main.
                    if (!isMainAccount(db, ownerUuid)) {
                        deny(event, "database-error");
                        audit(uuid, username, ip,
                                "LOGIN_BLOCKED",
                                "Alt owner Main account does not exist.");
                        return;
                    }

                    // Main ban blocks every linked Alt.
                    if (isBanned(db, ownerUuid)) {
                        deny(event, "&cYour Main Account is banned.");
                        audit(uuid, username, ip,
                                "LOGIN_BLOCKED",
                                "Linked Main account is banned: " + ownerUuid);
                        return;
                    }

                    audit(uuid, username, ip,
                            "AUTHORIZED_ALT_LOGIN",
                            "Authorized Alt. Main UUID: " + ownerUuid);

                    return;
                }

                // 6. Check pending or denied account status.
                String pendingStatus = getPendingStatus(db, uuid);

                if ("DENIED".equalsIgnoreCase(pendingStatus)) {
                    deny(event, "account-denied-login");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED",
                            "Account approval was denied.");
                    return;
                }

                if (pendingStatus != null) {
                    deny(event, "approval-required");
                    audit(uuid, username, ip,
                            "LOGIN_BLOCKED",
                            "Account is not approved. Status: " + pendingStatus);
                    return;
                }

                // 7. Unknown UUIDs are never automatically registered.
                deny(event, "approval-required");

                audit(uuid, username, ip,
                        "UNKNOWN_ACCOUNT_BLOCKED",
                        "UUID is not registered as Main or approved Alt.");

            } catch (SQLException exception) {

                plugin.getLogger().log(
                        Level.SEVERE,
                        "Account verification failed for " + username,
                        exception
                );

                // Fail closed if database verification fails.
                deny(event, "database-error");
            }
        }
    }

    private boolean isBanned(Connection db, String uuid)
            throws SQLException {

        String sql = """
                SELECT 1
                FROM account_bans
                WHERE player_uuid = ?
                LIMIT 1
                """;

        try (PreparedStatement ps = db.prepareStatement(sql)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isMainAccount(Connection db, String uuid)
            throws SQLException {

        String sql = """
                SELECT 1
                FROM main_accounts
                WHERE main_uuid = ?
                LIMIT 1
                """;

        try (PreparedStatement ps = db.prepareStatement(sql)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private String getAuthorizedOwner(Connection db, String altUuid)
            throws SQLException {

        String sql = """
                SELECT owner_uuid
                FROM authorized_accounts
                WHERE authorized_uuid = ?
                LIMIT 1
                """;

        try (PreparedStatement ps = db.prepareStatement(sql)) {

            ps.setString(1, altUuid);

            try (ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {
                    return rs.getString("owner_uuid");
                }
            }
        }

        return null;
    }

    private String getPendingStatus(Connection db, String uuid)
            throws SQLException {

        String sql = """
                SELECT status
                FROM pending_alt_accounts
                WHERE uuid = ?
                LIMIT 1
                """;

        try (PreparedStatement ps = db.prepareStatement(sql)) {

            ps.setString(1, uuid);

            try (ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {
                    return rs.getString("status");
                }
            }
        }

        return null;
    }

    private void deny(PlayerLoginEvent event, String message) {

        String finalMessage;

        if ("database-error".equals(message)
                || "approval-required".equals(message)
                || "account-denied-login".equals(message)) {

            finalMessage = plugin.getMessage(message);

        } else {
            finalMessage = plugin.color(message);
        }

        event.disallow(
                PlayerLoginEvent.Result.KICK_OTHER,
                finalMessage
        );
    }

    private void audit(
            String uuid,
            String username,
            String ip,
            String action,
            String details
    ) {

        plugin.logAudit(
                uuid,
                username,
                ip,
                action,
                details
        );
    }
}

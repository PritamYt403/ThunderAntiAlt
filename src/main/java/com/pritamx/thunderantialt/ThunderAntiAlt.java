
package com.pritamx.thunderantialt;

import com.pritamx.thunderantialt.license.LicenseManager;
import com.pritamx.thunderantialt.license.LicenseStatus;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.PluginManager;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import java.util.logging.Level;

public final class ThunderAntiAlt extends JavaPlugin {

    private Connection connection;
    private FileConfiguration messages;
    private final Object databaseLock = new Object();
    private LicenseManager licenseManager;
    private ServerAnnouncementTask announcementTask;

    private static final int DATABASE_VERSION = 2;

    @Override
    public void onEnable() {

        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().severe("Could not create plugin directory.");
            disableSelf();
            return;
        }

        licenseManager = new LicenseManager(this);

        LicenseStatus status = licenseManager.checkLicense();

        if (status != LicenseStatus.ACTIVE) {

            if (status == LicenseStatus.INVALID) {
                getLogger().severe(
                        "License is missing or invalid. Check plugins/ThunderAntiAlt/license.yml."
                );
            } else {
                getLogger().severe("Could not load the license file.");
            }

            disableSelf();
            return;
        }

        getLogger().info("License verified successfully.");

        saveDefaultConfig();
        saveResourceIfMissing("messages.yml");
        loadMessages();

        try {

            openDatabase();

            // Never silently accept an unknown or newer schema.
            validateDatabaseVersionBeforeChanges();

            createTables();

            synchronized (databaseLock) {
                DatabaseIntegrity.installAndVerify(
                        getDatabaseConnection()
                );
            }

            verifyDatabase();

        } catch (Exception exception) {

            getLogger().log(
                    Level.SEVERE,
                    "Database initialization or integrity verification failed. "
                            + "Plugin startup will be stopped. Existing data "
                            + "has not been automatically deleted.",
                    exception
            );

            closeDatabase();
            disableSelf();
            return;
        }

        PluginManager manager = getServer().getPluginManager();

        manager.registerEvents(new AccountListener(this), this);

        if (getCommand("thunderantialt") == null) {

            getLogger().severe(
                    "Command 'thunderantialt' is missing from plugin.yml."
            );

            closeDatabase();
            disableSelf();
            return;
        }

        getCommand("thunderantialt")
                .setExecutor(new AdminCommands(this));

        announcementTask = new ServerAnnouncementTask(this);
        announcementTask.start();

        getLogger().info("------------------------------------");
        getLogger().info("ThunderAntiAlt enabled successfully.");
        getLogger().info("Database version: " + DATABASE_VERSION);
        getLogger().info("Permanent account storage: enabled");
        getLogger().info("Alt approval storage: enabled");
        getLogger().info("Account ban storage: enabled");
        getLogger().info("Database relationship protection: enabled");
        getLogger().info("Server announcements: enabled");
        getLogger().info("------------------------------------");
    }

    private void disableSelf() {
        getServer().getPluginManager().disablePlugin(this);
    }

    private void saveResourceIfMissing(String name) {

        File file = new File(getDataFolder(), name);

        if (!file.exists()) {
            saveResource(name, false);
        }
    }

    private void loadMessages() {

        messages = YamlConfiguration.loadConfiguration(
                new File(getDataFolder(), "messages.yml")
        );
    }

    public void reloadPluginSettings() {

        reloadConfig();
        loadMessages();

        if (announcementTask != null) {
            announcementTask.start();
        }
    }

    /**
     * Opens SQLite database safely.
     */
    private void openDatabase() throws SQLException {

        String configuredPath = getConfig().getString(
                "database.file",
                "accounts.db"
        );

        if (configuredPath == null || configuredPath.isBlank()) {
            configuredPath = "accounts.db";
        }

        File databaseFile = new File(
                getDataFolder(),
                configuredPath
        );

        try {

            String basePath = getDataFolder().getCanonicalPath();
            String databasePath = databaseFile.getCanonicalPath();

            if (!databasePath.equals(basePath)
                    && !databasePath.startsWith(
                            basePath + File.separator
                    )) {

                throw new SQLException(
                        "Database path must stay inside the plugin folder."
                );
            }

        } catch (IOException exception) {

            throw new SQLException(
                    "Could not resolve database path.",
                    exception
            );
        }

        File parent = databaseFile.getParentFile();

        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new SQLException("Could not create database directory.");
        }

        connection = DriverManager.getConnection(
                "jdbc:sqlite:" + databaseFile.getAbsolutePath()
        );

        try (Statement statement = connection.createStatement()) {

            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 10000");
            statement.execute("PRAGMA journal_mode = WAL");
            statement.execute("PRAGMA synchronous = FULL");
            statement.execute("PRAGMA temp_store = MEMORY");
        }
    }

    /**
     * Checks the existing schema version before making schema changes.
     *
     * Version 0 is accepted only for a genuinely new database.
     * Unknown old versions and newer versions fail closed.
     */
    private void validateDatabaseVersionBeforeChanges()
            throws SQLException {

        synchronized (databaseLock) {

            boolean metadataExists = tableExists(
                    connection,
                    "database_metadata"
            );

            if (!metadataExists) {

                if (hasExistingApplicationTables(connection)) {
                    throw new SQLException(
                            "Existing database has no schema version. "
                                    + "Automatic migration is unsafe. "
                                    + "Back up and inspect this database first."
                    );
                }

                // A genuinely new database.
                return;
            }

            String versionValue = null;

            try (PreparedStatement ps = connection.prepareStatement("""
                    SELECT metadata_value
                    FROM database_metadata
                    WHERE metadata_key = 'schema_version'
                    LIMIT 1
                    """);
                 ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {
                    versionValue = rs.getString("metadata_value");
                }
            }

            if (versionValue == null || versionValue.isBlank()) {
                throw new SQLException(
                        "Database schema version is missing."
                );
            }

            final int existingVersion;

            try {
                existingVersion = Integer.parseInt(versionValue);
            } catch (NumberFormatException exception) {
                throw new SQLException(
                        "Invalid database schema version: " + versionValue,
                        exception
                );
            }

            if (existingVersion > DATABASE_VERSION) {
                throw new SQLException(
                        "Database schema version " + existingVersion
                                + " is newer than supported version "
                                + DATABASE_VERSION + "."
                );
            }

            if (existingVersion < DATABASE_VERSION) {
                throw new SQLException(
                        "Database schema version " + existingVersion
                                + " requires an explicit migration to version "
                                + DATABASE_VERSION
                                + ". Automatic migration is not implemented. "
                                + "Database data has been preserved."
                );
            }
        }
    }

    private boolean hasExistingApplicationTables(Connection db)
            throws SQLException {

        String[] applicationTables = {
                "main_accounts",
                "accounts",
                "authorized_accounts",
                "account_bans",
                "pending_alt_accounts",
                "audit_logs"
        };

        for (String table : applicationTables) {
            if (tableExists(db, table)) {
                return true;
            }
        }

        return false;
    }

    private boolean tableExists(Connection db, String table)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = ?
                LIMIT 1
                """)) {

            ps.setString(1, table);

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Creates the current database schema.
     * Existing account data is preserved.
     */
    private void createTables() throws SQLException {

        synchronized (databaseLock) {

            boolean oldAutoCommit = connection.getAutoCommit();
            Throwable originalException = null;

            try {

                connection.setAutoCommit(false);

                try (Statement statement = connection.createStatement()) {

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS database_metadata (
                            metadata_key TEXT PRIMARY KEY,
                            metadata_value TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS main_accounts (
                            main_uuid TEXT PRIMARY KEY,
                            username TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            last_seen TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS accounts (
                            uuid TEXT PRIMARY KEY,
                            username TEXT NOT NULL,
                            ip_address TEXT,
                            account_limit INTEGER NOT NULL DEFAULT 1,
                            approved INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            last_seen TEXT
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS authorized_accounts (
                            owner_uuid TEXT NOT NULL,
                            authorized_uuid TEXT PRIMARY KEY,
                            created_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS account_bans (
                            player_uuid TEXT PRIMARY KEY,
                            username TEXT NOT NULL,
                            reason TEXT,
                            banned_by TEXT,
                            created_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS pending_alt_accounts (
                            uuid TEXT PRIMARY KEY,
                            username TEXT NOT NULL,
                            ip_address TEXT NOT NULL,
                            main_uuid TEXT NOT NULL,
                            first_seen TEXT NOT NULL,
                            last_seen TEXT NOT NULL,
                            attempts INTEGER NOT NULL DEFAULT 1,
                            status TEXT NOT NULL DEFAULT 'PENDING'
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS ip_limits (
                            ip_address TEXT PRIMARY KEY,
                            max_accounts INTEGER NOT NULL,
                            updated_by TEXT,
                            updated_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS ip_main_accounts (
                            ip_address TEXT PRIMARY KEY,
                            main_uuid TEXT NOT NULL,
                            username TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            uuid TEXT,
                            username TEXT,
                            ip_address TEXT,
                            action TEXT NOT NULL,
                            details TEXT,
                            created_at TEXT NOT NULL
                        )
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_accounts_ip
                        ON accounts(ip_address)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_audit_uuid
                        ON audit_logs(uuid)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_audit_username
                        ON audit_logs(username)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_pending_ip
                        ON pending_alt_accounts(ip_address)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_pending_main
                        ON pending_alt_accounts(main_uuid, status)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_authorized_owner
                        ON authorized_accounts(owner_uuid)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_bans_username
                        ON account_bans(username)
                        """);

                    statement.executeUpdate("""
                        CREATE INDEX IF NOT EXISTS idx_main_username
                        ON main_accounts(username)
                        """);
                }

                saveDatabaseVersion();

                connection.commit();

            } catch (SQLException | RuntimeException | Error exception) {

                originalException = exception;

                try {
                    connection.rollback();
                } catch (SQLException rollbackError) {
                    exception.addSuppressed(rollbackError);
                }

                throw exception;

            } finally {

                try {
                    connection.setAutoCommit(oldAutoCommit);
                } catch (SQLException restoreError) {

                    if (originalException != null) {
                        originalException.addSuppressed(restoreError);
                    } else {
                        throw restoreError;
                    }
                }
            }
        }
    }

    /**
     * Stores the current schema version.
     * Called only after version validation and schema creation.
     */
    private void saveDatabaseVersion() throws SQLException {

        String sql = """
            INSERT INTO database_metadata
                (metadata_key, metadata_value, updated_at)
            VALUES ('schema_version', ?, ?)
            ON CONFLICT(metadata_key) DO UPDATE SET
                metadata_value = excluded.metadata_value,
                updated_at = excluded.updated_at
            """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, String.valueOf(DATABASE_VERSION));
            ps.setString(2, Instant.now().toString());

            ps.executeUpdate();
        }
    }

    /**
     * Verifies required tables and schema version.
     */
    private void verifyDatabase() throws SQLException {

        String[] requiredTables = {
                "database_metadata",
                "main_accounts",
                "accounts",
                "authorized_accounts",
                "account_bans",
                "pending_alt_accounts",
                "audit_logs"
        };

        for (String table : requiredTables) {

            if (!tableExists(connection, table)) {
                throw new SQLException(
                        "Required database table is missing: " + table
                );
            }
        }

        try (PreparedStatement ps = connection.prepareStatement("""
                SELECT metadata_value
                FROM database_metadata
                WHERE metadata_key = 'schema_version'
                LIMIT 1
                """);
             ResultSet rs = ps.executeQuery()) {

            if (!rs.next()) {
                throw new SQLException(
                        "Database schema version record is missing."
                );
            }

            int version;

            try {
                version = Integer.parseInt(rs.getString("metadata_value"));
            } catch (NumberFormatException exception) {
                throw new SQLException(
                        "Database schema version is invalid.",
                        exception
                );
            }

            if (version != DATABASE_VERSION) {
                throw new SQLException(
                        "Expected database version " + DATABASE_VERSION
                                + " but found " + version
                );
            }
        }

        getLogger().info(
                "Database integrity verification completed."
        );
    }

    public Connection getDatabaseConnection() {
        return connection;
    }

    public Object getDatabaseLock() {
        return databaseLock;
    }

    public String getMessage(String key) {

        String prefix = messages == null
                ? ""
                : messages.getString("prefix", "");

        String message = messages == null
                ? key
                : messages.getString("messages." + key, key);

        return color(prefix + message);
    }

    public String getMessage(
            String key,
            Map<String, String> replacements
    ) {

        String message = getMessage(key);

        if (replacements != null) {

            for (Map.Entry<String, String> entry
                    : replacements.entrySet()) {

                message = message.replace(
                        "{" + entry.getKey() + "}",
                        entry.getValue() == null
                                ? ""
                                : entry.getValue()
                );
            }
        }

        return message;
    }

    public void sendMessage(CommandSender sender, String key) {
        sender.sendMessage(getMessage(key));
    }

    public void sendMessage(
            CommandSender sender,
            String key,
            Map<String, String> replacements
    ) {
        sender.sendMessage(getMessage(key, replacements));
    }

    public String color(String text) {
        return ChatColor.translateAlternateColorCodes('&', text);
    }

    /**
     * Writes security audit logs.
     */
    public void logAudit(
            String uuid,
            String username,
            String ipAddress,
            String action,
            String details
    ) {

        synchronized (databaseLock) {

            if (connection == null) {
                getLogger().warning(
                        "Audit event could not be stored: " + action
                );
                return;
            }

            String sql = """
                INSERT INTO audit_logs
                    (uuid, username, ip_address, action, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """;

            try (PreparedStatement statement =
                         connection.prepareStatement(sql)) {

                statement.setString(1, uuid);
                statement.setString(2, username);
                statement.setString(3, ipAddress);
                statement.setString(4, action);
                statement.setString(5, details);
                statement.setString(6, Instant.now().toString());

                statement.executeUpdate();

            } catch (SQLException exception) {

                getLogger().log(
                        Level.SEVERE,
                        "Could not write audit log.",
                        exception
                );
            }
        }
    }

    @Override
    public void onDisable() {

        if (announcementTask != null) {
            announcementTask.stop();
        }

        closeDatabase();

        getLogger().info("ThunderAntiAlt disabled.");
    }

    /**
     * Safely closes SQLite connection.
     */
    private void closeDatabase() {

        synchronized (databaseLock) {

            if (connection != null) {

                try {
                    connection.close();

                } catch (SQLException exception) {

                    getLogger().log(
                            Level.WARNING,
                            "Could not close database.",
                            exception
                    );

                } finally {
                    connection = null;
                }
            }
        }
    }
}


package com.pritamx.thunderantialt;

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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import java.util.logging.Level;

public final class ThunderAntiAlt extends JavaPlugin {

    // Preserved from the previous version.
    private static final String LICENSE_KEY =
            "TAlt-X9vQ-7mKp-4RzN-8wHd-2LcF-6sYt";

    private Connection connection;
    private FileConfiguration messages;
    private final Object databaseLock = new Object();

    @Override
    public void onEnable() {
        saveDefaultConfig();

        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().severe("Could not create plugin directory.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        saveResourceIfMissing("messages.yml");

        if (!checkLicense()) {
            getLogger().severe("License validation failed. Plugin disabled.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        loadMessages();

        try {
            openDatabase();
            createTables();
        } catch (Exception exception) {
            getLogger().log(
                    Level.SEVERE,
                    "Database initialization failed.",
                    exception
            );
            closeDatabase();
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // Register the player login listener and admin command.
        PluginManager manager = getServer().getPluginManager();
        manager.registerEvents(new AccountListener(this), this);

        if (getCommand("thunderantialt") == null) {
            getLogger().severe(
                    "Command 'thunderantialt' is missing from plugin.yml."
            );
            closeDatabase();
            manager.disablePlugin(this);
            return;
        }

        getCommand("thunderantialt").setExecutor(new AdminCommands(this));

        getLogger().info("ThunderAntiAlt enabled successfully.");
    }

    private void saveResourceIfMissing(String name) {
        File file = new File(getDataFolder(), name);

        if (!file.exists()) {
            saveResource(name, false);
        }
    }

    private boolean checkLicense() {
        File file = new File(getDataFolder(), "license.yml");

        if (!file.exists()) {
            try {
                YamlConfiguration license = new YamlConfiguration();
                license.set("license-key", LICENSE_KEY);
                license.save(file);
            } catch (IOException exception) {
                getLogger().log(
                        Level.SEVERE,
                        "Could not create license.yml.",
                        exception
                );
                return false;
            }
        }

        FileConfiguration license = YamlConfiguration.loadConfiguration(file);
        String suppliedKey = license.getString("license-key", "");

        return LICENSE_KEY.equals(suppliedKey);
    }

    private void loadMessages() {
        File file = new File(getDataFolder(), "messages.yml");
        messages = YamlConfiguration.loadConfiguration(file);
    }

    public void reloadPluginSettings() {
        reloadConfig();
        loadMessages();
    }

    private void openDatabase() throws SQLException {
        String configuredPath = getConfig().getString(
                "database.file", "accounts.db"
        );

        if (configuredPath == null || configuredPath.isBlank()) {
            configuredPath = "accounts.db";
        }

        File databaseFile = new File(getDataFolder(), configuredPath);

        try {
            String basePath = getDataFolder().getCanonicalPath();
            String databasePath = databaseFile.getCanonicalPath();

            if (!databasePath.equals(basePath)
                    && !databasePath.startsWith(basePath + File.separator)) {
                throw new SQLException(
                        "Database path must stay inside the plugin folder."
                );
            }
        } catch (IOException exception) {
            throw new SQLException("Could not resolve database path.", exception);
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
            statement.execute("PRAGMA busy_timeout = 5000");
        }
    }

    private void createTables() throws SQLException {
        synchronized (databaseLock) {
            try (Statement statement = connection.createStatement()) {
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
                    CREATE TABLE IF NOT EXISTS ip_limits (
                        ip_address TEXT PRIMARY KEY,
                        max_accounts INTEGER NOT NULL,
                        updated_by TEXT,
                        updated_at TEXT NOT NULL
                    )
                    """);

                statement.executeUpdate(
                        "CREATE INDEX IF NOT EXISTS idx_accounts_ip " +
                        "ON accounts(ip_address)"
                );

                statement.executeUpdate(
                        "CREATE INDEX IF NOT EXISTS idx_audit_uuid " +
                        "ON audit_logs(uuid)"
                );

                statement.executeUpdate(
                        "CREATE INDEX IF NOT EXISTS idx_audit_username " +
                        "ON audit_logs(username)"
                );
            }
        }
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
            for (Map.Entry<String, String> entry : replacements.entrySet()) {
                message = message.replace(
                        "{" + entry.getKey() + "}",
                        entry.getValue() == null ? "" : entry.getValue()
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
        closeDatabase();
        getLogger().info("ThunderAntiAlt disabled.");
    }

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

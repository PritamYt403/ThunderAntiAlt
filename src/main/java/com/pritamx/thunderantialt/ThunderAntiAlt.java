
package com.pritamx.thunderantialt;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public final class ThunderAntiAlt extends JavaPlugin {

    private static final String LICENSE_KEY =
            "TAlt-X9vQ-7mKp-4RzN-8wHd-2LcF-6sYt";

    private Connection database;

    public Connection getDatabase() {
        return database;
    }

    @Override
    public void onEnable() {
        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().severe("Cannot create plugin folder.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        File licenseFile = new File(getDataFolder(), "license.yml");

        if (!licenseFile.exists()) {
            try {
                YamlConfiguration license = new YamlConfiguration();
                license.set("license-key", "");
                license.save(licenseFile);
            } catch (IOException e) {
                getLogger().severe("Cannot create license.yml.");
            }

            getLogger().warning("Add your license key to license.yml.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        String key = YamlConfiguration.loadConfiguration(licenseFile)
                .getString("license-key", "").trim();

        if (!LICENSE_KEY.equals(key)) {
            getLogger().severe("Invalid license. Plugin disabled.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        saveDefaultConfig();

        if (!new File(getDataFolder(), "messages.yml").exists()) {
            saveResource("messages.yml", false);
        }

        if (!openDatabase()) {
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        if (getCommand("thunderantialt") != null) {
            getCommand("thunderantialt").setExecutor(
                    new AdminCommands(this));
        } else {
            getLogger().severe(
                    "Command thunderantialt is missing from plugin.yml!");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        getServer().getPluginManager().registerEvents(
                new AccountListener(this), this);

        getLogger().info("ThunderAntiAlt enabled!");
    }

    private boolean openDatabase() {
        try {
            File file = new File(getDataFolder(), "accounts.db");

            database = DriverManager.getConnection(
                    "jdbc:sqlite:" + file.getAbsolutePath());

            try (Statement statement = database.createStatement()) {
                statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS accounts (
                        uuid TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        ip_address TEXT,
                        account_limit INTEGER DEFAULT 1,
                        approved INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_seen TEXT
                    )
                    """);

                statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        player_uuid TEXT,
                        username TEXT,
                        ip_address TEXT,
                        event TEXT NOT NULL,
                        details TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """);

                statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS authorized_accounts (
                        owner_uuid TEXT NOT NULL,
                        account_uuid TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (owner_uuid, account_uuid)
                    )
                    """);
            }

            return true;
        } catch (SQLException e) {
            getLogger().severe("Database error: " + e.getMessage());
            return false;
        }
    }

    @Override
    public void onDisable() {
        if (database != null) {
            try {
                database.close();
            } catch (SQLException e) {
                getLogger().warning("Could not close database.");
            }
        }
    }
}

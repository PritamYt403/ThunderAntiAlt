
package com.pritamx.thunderantialt.license;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;

public final class LicenseManager {

    private static final String FIXED_LICENSE_KEY =
            "THUNDER-PRITAMGAMING-2026113245";

    private final JavaPlugin plugin;

    public LicenseManager(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    public LicenseStatus checkLicense() {
        File folder = plugin.getDataFolder();
        File licenseFile = new File(folder, "license.yml");

        if (!folder.exists() && !folder.mkdirs()) {
            plugin.getLogger().severe("Cannot create plugin folder!");
            return LicenseStatus.UNAVAILABLE;
        }

        if (!licenseFile.exists()) {
            YamlConfiguration config = new YamlConfiguration();
            config.set("license-key", "");

            try {
                config.save(licenseFile);
                plugin.getLogger().info(
                        "license.yml created. Add your license key and restart."
                );
            } catch (IOException e) {
                plugin.getLogger().severe(
                        "Cannot create license.yml: " + e.getMessage()
                );
                return LicenseStatus.UNAVAILABLE;
            }

            return LicenseStatus.INVALID;
        }

        YamlConfiguration config =
                YamlConfiguration.loadConfiguration(licenseFile);

        String key = config.getString("license-key", "");

        if (key == null || !FIXED_LICENSE_KEY.equals(key.trim())) {
            plugin.getLogger().severe("Invalid or missing license key!");
            return LicenseStatus.INVALID;
        }

        return LicenseStatus.ACTIVE;
    }
}

package com.pritamx.thunderantialt.license;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class LicenseManager {

private final JavaPlugin plugin;
private final LicenseValidator validator = new LicenseValidator();
private File licenseFile;

public LicenseManager(JavaPlugin plugin) {
    this.plugin = plugin;
}

public LicenseStatus checkLicense() {
    licenseFile = new File(plugin.getDataFolder(), "license.yml");

    try {
        if (!plugin.getDataFolder().exists()
                && !plugin.getDataFolder().mkdirs()) {
            plugin.getLogger().severe(
                    "Could not create plugin data folder."
            );
            return LicenseStatus.UNAVAILABLE;
        }

        if (!licenseFile.exists()) {
            Files.writeString(
                    licenseFile.toPath(),
                    "license-key: \"\"\n"
            );
            plugin.getLogger().warning(
                    "Created license.yml. Add your license key and restart."
            );
            return LicenseStatus.INVALID;
        }

        YamlConfiguration config =
                YamlConfiguration.loadConfiguration(licenseFile);

        String key = config.getString("license-key", "");

        if (key == null || key.isBlank()) {
            plugin.getLogger().warning(
                    "Add your license key to plugins/"
                            + plugin.getName() + "/license.yml"
            );
            return LicenseStatus.INVALID;
        }

        return validator.validate(key.trim());

    } catch (IOException exception) {
        plugin.getLogger().severe(
                "Could not read or create license.yml: "
                        + exception.getMessage()
        );
        return LicenseStatus.UNAVAILABLE;
    }
}

}

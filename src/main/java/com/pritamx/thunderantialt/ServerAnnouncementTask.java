
package com.pritamx.thunderantialt;

import org.bukkit.ChatColor;
import org.bukkit.Sound;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.util.List;

public final class ServerAnnouncementTask {

    private static final long DEFAULT_INTERVAL_SECONDS = 300L;
    private static final long MAX_INTERVAL_SECONDS = 2_592_000L;

    private final ThunderAntiAlt plugin;

    private BukkitTask task;

    public ServerAnnouncementTask(ThunderAntiAlt plugin) {
        this.plugin = plugin;
    }

    public void start() {
        stop();

        if (!plugin.getConfig().getBoolean(
                "announcements.enabled", true)) {

            plugin.getLogger().info(
                    "Server announcements are disabled."
            );
            return;
        }

        long intervalSeconds = plugin.getConfig().getLong(
                "announcements.interval-seconds",
                DEFAULT_INTERVAL_SECONDS
        );

        if (intervalSeconds < 1) {
            plugin.getLogger().warning(
                    "Invalid announcement interval. Using default: "
                            + DEFAULT_INTERVAL_SECONDS + " seconds."
            );

            intervalSeconds = DEFAULT_INTERVAL_SECONDS;
        }

        if (intervalSeconds > MAX_INTERVAL_SECONDS) {
            plugin.getLogger().warning(
                    "Announcement interval exceeds the maximum. "
                            + "It has been limited to 30 days."
            );

            intervalSeconds = MAX_INTERVAL_SECONDS;
        }

        // Safe because intervalSeconds is now bounded.
        long intervalTicks = intervalSeconds * 20L;

        task = plugin.getServer().getScheduler().runTaskTimer(
                plugin,
                this::sendAnnouncement,
                intervalTicks,
                intervalTicks
        );

        plugin.getLogger().info(
                "Server announcements enabled. Interval: "
                        + intervalSeconds + " seconds."
        );
    }

    private void sendAnnouncement() {

        if (!plugin.isEnabled()) {
            stop();
            return;
        }

        if (plugin.getServer().getOnlinePlayers().isEmpty()) {
            return;
        }

        File messagesFile = new File(
                plugin.getDataFolder(),
                "messages.yml"
        );

        if (!messagesFile.isFile()) {
            plugin.getLogger().warning(
                    "messages.yml is missing. Announcement skipped."
            );
            return;
        }

        YamlConfiguration messages =
                YamlConfiguration.loadConfiguration(messagesFile);

        String prefix = messages.getString("prefix", "");

        List<String> lines = messages.getStringList(
                "messages.server-promo"
        );

        if (lines.isEmpty()) {
            plugin.getLogger().warning(
                    "No announcement messages found in messages.yml."
            );
            return;
        }

        for (Player player : plugin.getServer().getOnlinePlayers()) {

            if (player == null || !player.isOnline()) {
                continue;
            }

            player.playSound(
                    player.getLocation(),
                    Sound.BLOCK_NOTE_BLOCK_PLING,
                    0.7f,
                    1.3f
            );

            for (String line : lines) {

                if (line == null) {
                    continue;
                }

                String formatted =
                        ChatColor.translateAlternateColorCodes(
                                '&',
                                prefix + line
                        );

                player.sendMessage(formatted);
            }
        }
    }

    public void stop() {

        if (task != null) {
            task.cancel();
            task = null;
        }
    }
}

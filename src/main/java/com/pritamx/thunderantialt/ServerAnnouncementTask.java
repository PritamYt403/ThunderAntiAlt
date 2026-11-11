
package com.pritamx.thunderantialt;

import org.bukkit.ChatColor;
import org.bukkit.Sound;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.util.List;

public final class ServerAnnouncementTask {

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
                "announcements.interval-seconds", 300
        );

        if (intervalSeconds < 1) {
            intervalSeconds = 300;
        }

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

        if (plugin.getServer().getOnlinePlayers().isEmpty()) {
            return;
        }

        File messagesFile = new File(
                plugin.getDataFolder(),
                "messages.yml"
        );

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

            // Notification sound.
            player.playSound(
                    player.getLocation(),
                    Sound.BLOCK_NOTE_BLOCK_PLING,
                    0.7f,
                    1.3f
            );

            // Send announcement.
            for (String line : lines) {

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

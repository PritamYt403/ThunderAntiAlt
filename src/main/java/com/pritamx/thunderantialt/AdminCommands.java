package com.pritamx.thunderantialt;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

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
            String[] args) {

        if (!sender.hasPermission("thunderantialt.admin")) {
            sender.sendMessage(color("&cYou don't have permission."));
            return true;
        }

        if (args.length != 2) {
            sender.sendMessage(color(
                    "&e/thunderantialt approve <player>"));
            sender.sendMessage(color(
                    "&e/thunderantialt info <player>"));
            return true;
        }

        String action = args[0].toLowerCase();
        String username = args[1];

        if (!action.equals("approve") && !action.equals("info")) {
            sender.sendMessage(color("&cUnknown command."));
            return true;
        }

        Connection database = plugin.getDatabase();

        if (database == null) {
            sender.sendMessage(color("&cDatabase unavailable."));
            return true;
        }

        try {
            if (action.equals("approve")) {
                try (PreparedStatement statement = database.prepareStatement(
                        "UPDATE accounts SET approved = 1 WHERE LOWER(username) = LOWER(?)")) {
                    statement.setString(1, username);

                    int updated = statement.executeUpdate();

                    if (updated == 0) {
                        sender.sendMessage(color(
                                "&cAccount not found: " + username));
                    } else {
                        sender.sendMessage(color(
                                "&aApproved account: " + username));
                    }
                }
                return true;
            }

            try (PreparedStatement statement = database.prepareStatement(
                    "SELECT uuid, username, ip_address, approved, created_at, last_seen FROM accounts WHERE LOWER(username) = LOWER(?)")) {
                statement.setString(1, username);

                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        sender.sendMessage(color("&cAccount not found."));
                        return true;
                    }

                    String ip = result.getString("ip_address");
                    String maskedIp = maskIp(ip);

                    sender.sendMessage(color("&6--- ThunderAntiAlt Info ---"));
                    sender.sendMessage(color(
                            "&eUsername: &f" + result.getString("username")));
                    sender.sendMessage(color(
                            "&eUUID: &f" + result.getString("uuid")));
                    sender.sendMessage(color("&eIP: &f" + maskedIp));
                    sender.sendMessage(color(
                            "&eApproved: &f"
                                    + (result.getInt("approved") == 1
                                    ? "Yes" : "No")));
                    sender.sendMessage(color(
                            "&eCreated: &f" + result.getString("created_at")));
                    sender.sendMessage(color(
                            "&eLast seen: &f" + result.getString("last_seen")));
                }
            }
        } catch (Exception exception) {
            plugin.getLogger().severe(
                    "Admin command failed: " + exception.getMessage());
            sender.sendMessage(color("&cCommand failed. Check server logs."));
        }

        return true;
    }

    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "Unknown";
        }

        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".***.***";
            }
        }

        if (ip.contains(":")) {
            int lastColon = ip.lastIndexOf(':');
            return ip.substring(0, lastColon) + ":****";
        }

        return "Hidden";
    }

    private String color(String message) {
        return ChatColor.translateAlternateColorCodes('&', message);
    }
              }

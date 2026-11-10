# ⚡ ThunderAntiAlt

**Minecraft Alternate Account Management & Authorization Plugin**

Made by Pritam.

ThunderAntiAlt is a Minecraft server plugin designed to help server administrators manage alternate accounts, review account authorization requests, enforce configurable IP-based account limits, and maintain account activity logs.

## ✨ Features

- SQLite database for persistent account records
- Main-account and alternate-account tracking
- Pending alternate-account approval workflow
- Admin approval and denial controls
- Configurable account limits per IP address
- Account removal and information lookup
- Audit logs for account-related actions
- Admin notifications for account events
- Permission-based administrative access
- Configurable messages in `messages.yml`
- Settings managed through `config.yml`
- Database error handling with fail-closed configuration
- Offline fixed license-key verification

## 📥 Installation

1. Download the compatible `ThunderAntiAlt.jar` from GitHub Releases or Actions artifacts.
2. Stop your Minecraft server.
3. Upload the JAR to your server's `plugins/` directory.
4. Start the server once. The plugin will generate its configuration files.
5. Stop the server.
6. Open `plugins/ThunderAntiAlt/license.yml`.
7. Add the fixed license key:

   ```yaml
   license-key: "THUNDER-PRITAMGAMING-2026113245"
   ```

8. Save the file.
9. Start your server again.

**Important:** The plugin will enable only if the license key matches the expected key embedded in the plugin JAR.

License verification is completely offline. No Cloudflare Worker, external API, or internet connection is required.

## 🎮 Admin Commands

| Command | Description |
|---|---|
| `/ta reload` | Reload plugin settings |
| `/ta adduser` | Add or register an account |
| `/ta info` | View account information |
| `/ta pending` | View pending account requests |
| `/ta approve` | Approve an alternate-account request |
| `/ta deny` | Deny an alternate-account request |
| `/ta removeuser` | Remove an account |
| `/ta limit` | Manage account limits |

Use `/ta` without arguments to display command help. Check the installed version's command usage for required arguments.

## ⚙️ Configuration

The plugin generates or uses these files:

- `config.yml` — Database path, account limits, and security settings.
- `messages.yml` — Configurable messages.
- `license.yml` — Offline license-key configuration.
- SQLite database — Persistent account and audit information.

Back up your database and configuration files before updating the plugin.

## 🔐 Security Notes

- Account records are stored persistently in SQLite.
- Database failures are handled according to the configured fail-closed policy.
- IP addresses can be shared by multiple legitimate players.
- IP-based limits alone cannot reliably identify a player's physical device.
- The offline license key is shared and embedded in the JAR. It is not a secure per-server entitlement system.

## 🛠️ Building from Source

Requirements depend on the target Minecraft version and the project's Maven configuration.

```bash
mvn clean package
```

After a successful build, check the project's `target/` directory for the generated JAR.

## 👨‍💻 Developer

**Pritam**

Project: ThunderAntiAlt

## 📄 License

Refer to the repository's license and distribution terms before redistributing the plugin.

⚡ ThunderAntiAlt

Minecraft Alternate Account Management & Authorization Plugin
Made by Pritam

ThunderAntiAlt is a Minecraft server plugin designed to help server administrators manage alternate accounts, review account authorization requests, enforce configurable IP-based account limits, and maintain account activity logs.

✨ Features

- SQLite database for persistent account records
- Main-account and alternate-account tracking
- Pending alternate-account approval workflow
- Admin approval and denial controls
- Configurable account limits per IP address
- Account removal and information lookup
- Audit logs for account-related actions
- Admin notifications for account events
- Permission-based administrative access
- Configurable messages in "messages.yml"
- Settings managed through "config.yml"
- Database error handling with fail-closed configuration
- License-key verification

📥 Installation

1. Download the compatible "ThunderAntiAlt.jar" from the project's GitHub Releases or Actions artifacts.
2. Stop your Minecraft server.
3. Upload the JAR to your server's "plugins/" directory.
4. Start the server to generate the plugin configuration files.
5. Configure "config.yml", "messages.yml", and "license.yml".
6. Add your valid license key to "license.yml".
7. Restart the server and check the console for startup errors.

Important: The plugin will not enable if license verification fails or database initialization fails.

🎮 Admin Commands

The intended administrative command set is:

Command| Description
"/ta reload"| Reload plugin settings
"/ta adduser"| Add or register an account through the admin workflow
"/ta info"| View account information
"/ta pending"| View pending account requests
"/ta approve"| Approve an alternate-account request
"/ta deny"| Deny an alternate-account request
"/ta removeuser"| Remove an account
"/ta limit"| Manage account limits

Use "/ta" without arguments to display the command help. Check the installed version's command usage for required arguments.

⚙️ Configuration

The plugin generates or uses these files:

- "config.yml" — database path, account limits, and security settings
- "messages.yml" — configurable messages
- "license.yml" — license key configuration
- SQLite database — persistent account and audit information

Back up your database and configuration files before updating the plugin.

🔐 Security Notes

- Account records are stored persistently in SQLite.
- Database failures should be handled according to the configured fail-closed policy.
- IP addresses can be shared by multiple legitimate players, such as people using the same household or network.
- IP-based limits alone cannot reliably identify a player's physical device.
- Protect your license key and database backups.

🛠️ Building from Source

Requirements depend on the target Minecraft version and the project's Maven configuration.

mvn clean package

After a successful build, check the project's "target/" directory for the generated JAR.

👨‍💻 Developer

Pritam
Project: ThunderAntiAlt

📄 License

Refer to the repository's license and distribution terms before redistributing the plugin.

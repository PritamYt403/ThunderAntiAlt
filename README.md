
# ⚡ ThunderAntiAlt

**Minecraft Main Account & Alternate Account Authorization Plugin**

Developed by Pritam.

ThunderAntiAlt helps server administrators manage Main Accounts, approve alternate accounts, maintain account records, and enforce account authorization rules.

## ✨ Features

- SQLite database for persistent account records
- Main Account and Alt Account relationships
- Pending account approval workflow
- Admin approval and denial controls
- Main and Alt account ban management
- Account information lookup
- Account activity and audit logging
- Admin notifications
- Permission-based administrative commands
- Configurable messages
- Database integrity checks and security triggers
- Fail-closed handling for database errors

## 📥 Installation

1. Download the compatible JAR from GitHub Actions artifacts or Releases.
2. Stop your Minecraft server.
3. Upload the JAR into the server's `plugins/` directory.
4. Start the server and allow the plugin to generate its files.
5. Configure the generated files as required.
6. Restart the server.

Back up your database and configuration before updating.

## 🎮 Admin Commands

| Command | Description |
|---|---|
| `/ta help` | Display available commands |
| `/ta setmain <uuid> <username>` | Register a Main Account |
| `/ta pending` | View pending accounts |
| `/ta approve <alt-uuid> <main-uuid>` | Approve and link an Alt |
| `/ta deny <alt-uuid>` | Deny an account |
| `/ta info <uuid>` | View account information |
| `/ta removeuser <alt-uuid>` | Remove Alt authorization |
| `/ta ban <uuid> [reason]` | Ban an account |
| `/ta unban <uuid>` | Unban an account |
| `/ta reload` | Reload configuration and messages |

Administrative commands require the `thunderantialt.admin` permission.

## ⚙️ Configuration

The plugin uses:

- `config.yml` — Database and security settings.
- `messages.yml` — Configurable messages.
- `license.yml` — Existing license configuration.
- `accounts.db` — SQLite account and audit database.

Some older IP-related configuration entries are retained for compatibility. Do not treat them as reliable account identity verification or as proof of account ownership.

## 🔐 Security Notes

- Main and Alt account relationships are stored in SQLite.
- Database integrity checks help prevent invalid account relationships.
- Main Account bans also apply to linked Alt accounts.
- Unknown accounts can be held for administrator approval.
- IP addresses are metadata, not proof of identity.
- Shared IP addresses do not necessarily mean accounts belong to the same person.
- In Offline Mode, UUIDs are derived from usernames. A matching username can therefore produce the same offline UUID.
- ThunderAntiAlt alone cannot prove ownership of a Minecraft account in Offline Mode. A trusted authentication integration, such as ThunderAuth, is needed before treating a login as authenticated.

**Important:** Do not consider an account secure merely because its UUID is registered or approved. Authentication must also succeed.

## 🛠️ Building from Source

Requirements:

- Java 21 for the Paper 1.21.x build.
- Java 25 for the Paper 26.x build.
- Maven.

Build using:

```bash
mvn clean package
```

The project also provides separate GitHub Actions build jobs for the supported targets.

Generated JAR files are available in the `target/` directory.

## 👨‍💻 Developer

**Pritam**

Project: ThunderAntiAlt

## 📄 License

Refer to the repository's license and distribution terms before redistributing the plugin.

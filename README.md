
# ThunderAntiAlt

**Advanced Anti-Alt Account Protection System**  
Made by **Pritam**

ThunderAntiAlt is a Paper plugin designed to limit alternate accounts and manage account access using persistent UUID/IP records and SQLite storage.

## Features

- Configurable account limit per IP
- Persistent player UUID and IP binding
- New-account approval system
- Admin-authorized additional accounts
- Persistent account bans and unbans
- Reset player IP binding
- Per-player IP account limits
- Account lookup and audit logs
- Admin alerts for account activity
- SQLite database persistence
- Configurable messages in `messages.yml`
- IP masking in general account information

## Requirements

- Java 21
- Paper 1.21.x

The project builds against Paper API 1.21.4. Other Minecraft/Paper versions require compatibility testing.

## Installation

1. Download `ThunderAntiAlt.jar` from the successful GitHub Actions build artifact.
2. Put the JAR in your server's `plugins` folder.
3. Start or restart the server.
4. Configure the generated files in `plugins/ThunderAntiAlt/`.

## Commands

| Command | Description |
|---|---|
| `/ta help` | Show available commands |
| `/ta info <player>` | Show general account information |
| `/ta lookup <player>` | Look up account details, including IP |
| `/ta logs <player>` | View account audit history |
| `/ta approve <player>` | Approve a pending account |
| `/ta adduser <player> <authorized-player>` | Authorize an additional account |
| `/ta removeuser <player> <authorized-player>` | Remove an account authorization |
| `/ta reset <player>` | Reset the player's IP binding |
| `/ta ban <player> [reason]` | Ban an account |
| `/ta unban <player>` | Remove an account ban |
| `/ta limit <player> <number>` | Set a player's IP account limit |
| `/ta clearlogs <player>` | Clear the player's audit history |
| `/ta reload` | Reload plugin settings |

Use `/ta help` in-game for command usage.

## Permissions

- `thunderantialt.admin` — access administration commands; default: operators
- `thunderantialt.bypass` — bypass account restrictions; default: nobody

## Configuration

The default configuration limits each IP to one account and requires approval for new accounts.

When `require-new-ip-approval` is enabled, a new account may be denied until an administrator approves it with `/ta approve <player>`.

Back up the plugin's database before making manual changes.

## Build from Source

Install Java 21 and Maven, then run:

```bash
mvn clean package
```

The output JAR is:

```text
target/ThunderAntiAlt.jar
```

GitHub Actions can build the plugin automatically. Download the JAR from the workflow's **Artifacts** section after a successful run.

## Security Notes

- `/ta lookup` can reveal full IP addresses. Restrict admin permission to trusted staff.
- IP-based restrictions are not reliable proof that two players are the same person; players may share networks or use different networks.
- Proxy and Floodgate configuration options are placeholders; integrations are not implemented yet.
- A license check embedded in a public plugin cannot securely protect a secret key.

## License

Review the repository's license before redistributing or modifying this project.

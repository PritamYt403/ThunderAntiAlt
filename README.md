# ThunderAntiAlt

**A Minecraft account/IP restriction plugin by Pritam.**

ThunderAntiAlt is intended for Paper servers using the Bukkit/Paper API. It stores account bindings and audit events in a local SQLite database.

## Current features

- SQLite persistence for account records and audit events
- Configurable default account limit per IP
- Optional administrator approval for new accounts
- IP binding checks for previously registered accounts
- Admin commands for account lookup, approval, logs, and authorization
- Optional permission bypass

## Requirements

- Java 21
- Maven 3.9+
- Paper 1.21.x (the current `pom.xml` targets Paper API `1.21.4-R0.1-SNAPSHOT`)

Compatibility with Minecraft 26.x and other server implementations has not yet been verified.

## Build

Run from the repository root:

```bash
mvn clean package
```

The plugin JAR will be created in `target/`.

GitHub Actions can build the plugin automatically after the workflow file is added at `.github/workflows/build.yml`.

## Install

1. Build the JAR.
2. Copy the JAR into the server's `plugins/` folder.
3. Start the server once so the plugin can create its data folder and `license.yml`.
4. Follow the license-key message in the server console, then restart the server.

The plugin currently uses a hardcoded license key in its Java source. This is not a secure licensing system: anyone with source/JAR access may be able to extract it. Do not treat it as strong copy protection.

## Configuration

The plugin's bundled `config.yml` contains defaults for account limits, approval, alerts, logging, and security settings. Review it before use.

Runtime data is intended to be stored under:

```text
plugins/ThunderAntiAlt/
├── license.yml
├── config.yml
├── messages.yml
└── accounts.db
```

`license.yml` and `accounts.db` are runtime-generated files; they should not be committed to the source repository.

## Commands

The current command implementation includes:

```text
/ta approve <player>
/ta info <player>
/ta lookup <player>
/ta logs <player>
/ta adduser <owner> <account>
/ta removeuser <owner> <account>
/ta reset <player>
/ta unban <player>
/ta limit <player> <number>
/ta reload
```

Only grant `thunderantialt.admin` to trusted administrators. The `unban` command and some authorization/limit behaviors still need additional implementation and testing before relying on them for a production server.

## Permissions

- `thunderantialt.admin` — administrator commands; defaults to operators.
- `thunderantialt.bypass` — bypasses the account checks; defaults to nobody.

## Important status

This project has not yet been verified by a successful build or a live-server test in this conversation. Test it on a private test server and keep backups of the plugin database before using it on a production server.

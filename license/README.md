# ThunderAntiAlt Offline License

This project uses a local fixed-key license check.

**No internet connection or external license API is required.** The plugin does not contact Cloudflare, GitHub, or any remote validation server.

## Setup Instructions

On the first server startup, the plugin automatically creates:

`plugins/ThunderAntiAlt/license.yml`

Initially, the file contains:

```yaml
license-key: ""
```

Open `license.yml` and enter the fixed license key:

```yaml
license-key: "THUNDER-PRITAMGAMING-2026113245"
```

Save the file and restart your Minecraft server.

## License Verification

- Correct license key: Plugin enables.
- Missing license key: Plugin does not enable.
- Incorrect license key: Plugin does not enable.
- License verification works completely offline.

## Security Note

This is a basic offline license check, not strong anti-piracy protection. The expected key is embedded in the plugin JAR and may be extracted by someone who can inspect or decompile it.

The same fixed key is shared across installations using this build.

Never commit private server data or database backups.

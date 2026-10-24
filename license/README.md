ThunderAntiAlt License Module

This folder contains the isolated license validation module for ThunderAntiAlt.

Cloudflare API endpoint:
"https://thunderantialt-license.h7198083.workers.dev/api/validate"

Method: "POST"

Request JSON:
"{"key":"YOUR_LICENSE_KEY"}"

The API response should include "valid" and "status" fields.

Never commit real license keys or admin credentials.

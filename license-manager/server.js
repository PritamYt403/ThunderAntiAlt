const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : undefined
});

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

const DURATIONS = {
  "1 hour": 60 * 60 * 1000,
  "1 day": 24 * 60 * 60 * 1000,
  "7 days": 7 * 24 * 60 * 60 * 1000,
  "30 days": 30 * 24 * 60 * 60 * 1000,
  "1 year": 365 * 24 * 60 * 60 * 1000
};

function hashKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function requireAdmin(req, res, next) {
  const supplied = req.get("authorization") || "";
  const expected = `Bearer ${ADMIN_TOKEN || ""}`;

  if (!ADMIN_TOKEN || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({ service: "ThunderAntiAlt License API", status: "online" });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.post("/api/admin/licenses", requireAdmin, async (req, res) => {
  const duration = req.body.duration;

  if (!Object.hasOwn(DURATIONS, duration)) {
    return res.status(400).json({
      error: "Choose 1 hour, 1 day, 7 days, 30 days, or 1 year"
    });
  }

  const key = `TAA-${crypto.randomBytes(24).toString("hex").toUpperCase()}`;
  const expiresAt = new Date(Date.now() + DURATIONS[duration]);

  try {
    await pool.query(
      `INSERT INTO licenses (key_hash, duration, expires_at, status)
       VALUES ($1, $2, $3, 'active')`,
      [hashKey(key), duration, expiresAt]
    );

    res.status(201).json({
      license_key: key,
      duration,
      expires_at: expiresAt.toISOString(),
      status: "active"
    });
  } catch (error) {
    console.error("License creation failed:", error.message);
    res.status(500).json({ error: "Could not create license" });
  }
});

app.get("/api/admin/licenses", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, duration, created_at, expires_at, status
       FROM licenses ORDER BY created_at DESC LIMIT 200`
    );
    res.json({ licenses: result.rows });
  } catch (error) {
    console.error("License listing failed:", error.message);
    res.status(500).json({ error: "Could not list licenses" });
  }
});

app.post("/api/admin/licenses/revoke", requireAdmin, async (req, res) => {
  const key = req.body.license_key;

  if (typeof key !== "string" || !key.startsWith("TAA-")) {
    return res.status(400).json({ error: "Invalid license key" });
  }

  try {
    const result = await pool.query(
      `UPDATE licenses SET status = 'revoked'
       WHERE key_hash = $1 AND status = 'active'
       RETURNING id`,
      [hashKey(key)]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Active license not found" });
    }

    res.json({ status: "revoked" });
  } catch (error) {
    console.error("Revocation failed:", error.message);
    res.status(500).json({ error: "Could not revoke license" });
  }
});

app.post("/api/validate", async (req, res) => {
  const key = req.body.license_key;

  if (typeof key !== "string" || key.length > 100) {
    return res.status(400).json({ valid: false, reason: "invalid_key" });
  }

  try {
    const result = await pool.query(
      `SELECT expires_at, status FROM licenses WHERE key_hash = $1`,
      [hashKey(key)]
    );

    if (!result.rowCount) {
      return res.json({ valid: false, reason: "not_found" });
    }

    const license = result.rows[0];

    if (license.status !== "active") {
      return res.json({ valid: false, reason: "revoked" });
    }

    if (new Date(license.expires_at).getTime() <= Date.now()) {
      await pool.query(
        `UPDATE licenses SET status = 'expired'
         WHERE key_hash = $1 AND status = 'active'`,
        [hashKey(key)]
      );
      return res.json({ valid: false, reason: "expired" });
    }

    res.json({
      valid: true,
      expires_at: new Date(license.expires_at).toISOString()
    });
  } catch (error) {
    console.error("Validation failed:", error.message);
    res.status(503).json({ valid: false, reason: "service_unavailable" });
  }
});

async function start() {
  if (!process.env.DATABASE_URL || !ADMIN_TOKEN) {
    throw new Error("DATABASE_URL and ADMIN_TOKEN environment variables are required");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) UNIQUE NOT NULL,
      duration TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired'))
    )
  `);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ThunderAntiAlt License API listening on ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
            

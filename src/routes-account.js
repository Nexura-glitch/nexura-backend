const express = require("express");
const bcrypt = require("bcrypt");
const { body, param, query } = require("express-validator");
const pool = require("./db");
const { requireAuth, requireAdmin, signToken, handleValidation, loginLimiter } = require("./middleware");

const router = express.Router();
const SALT_ROUNDS = 12;
const DUMMY_HASH = "$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv";

function generateAccountNumber() {
  const part = () => String(Math.floor(1000 + Math.random() * 9000));
  return `${part()} ${part()} ${part()}`;
}
function generateRoutingNumber() {
  let out = "";
  for (let i = 0; i < 9; i++) out += Math.floor(Math.random() * 10);
  return out;
}

const PUBLIC_USER_FIELDS = `
  id, first_name, last_name, email, phone, address, account_number, routing_number,
  account_type, balance, available, currency, verification_level, account_status,
  two_factor_enabled, last_access, last_ip, created_at
`;

router.post(
  "/auth/register",
  [
    body("firstName").trim().isLength({ min: 1, max: 100 }).escape(),
    body("lastName").trim().isLength({ min: 1, max: 100 }).escape(),
    body("email").trim().isEmail().normalizeEmail(),
    body("password").isLength({ min: 8 }),
  ],
  handleValidation,
  async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "Ya existe una cuenta con ese correo" });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, email, password_hash, account_number, routing_number)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING ${PUBLIC_USER_FIELDS}`,
      [firstName, lastName, email, passwordHash, generateAccountNumber(), generateRoutingNumber()]
    );
    const user = result.rows[0];
    const token = signToken({ userId: user.id, role: "client" });
    return res.status(201).json({ token, user });
  }
);

router.post(
  "/auth/login",
  loginLimiter,
  [body("email").trim().isEmail().normalizeEmail(), body("password").notEmpty()],
  handleValidation,
  async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !valid) return res.status(401).json({ error: "Correo o contraseña incorrectos" });
    if (user.account_status === "Suspendida") {
      return res.status(403).json({ error: "Esta cuenta ha sido suspendida. Contacte a la administración." });
    }

    await pool.query(`INSERT INTO access_log (user_id, ip_address) VALUES ($1, $2)`, [user.id, req.ip]);
    await pool.query(`UPDATE users SET last_access = now(), last_ip = $2 WHERE id = $1`, [user.id, req.ip]);

    const token = signToken({ userId: user.id, role: "client" });
    delete user.password_hash;
    return res.json({ token, user });
  }
);

router.post(
  "/auth/admin-login",
  loginLimiter,
  [body("email").trim().isEmail().normalizeEmail(), body("password").notEmpty()],
  handleValidation,
  async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM admins WHERE email = $1", [email]);
    const admin = result.rows[0];
    const valid = await bcrypt.compare(password, admin ? admin.password_hash : DUMMY_HASH);
    if (!admin || !valid) return res.status(401).json({ error: "Credenciales de administrador incorrectas" });

    const token = signToken({ userId: admin.id, role: "admin" });
    return res.json({ token, admin: { id: admin.id, name: admin.name, email: admin.email } });
  }
);

router.get("/users/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT ${PUBLIC_USER_FIELDS} FROM users WHERE id = $1`, [req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });
  return res.json(result.rows[0]);
});

router.patch(
  "/users/me",
  requireAuth,
  [
    body("phone").optional().trim().isLength({ max: 30 }).escape(),
    body("address").optional().trim().isLength({ max: 255 }).escape(),
    body("twoFactorEnabled").optional().isBoolean(),
  ],
  handleValidation,
  async (req, res) => {
    const fields = [];
    const values = [];
    let i = 1;
    if (req.body.phone !== undefined) { fields.push(`phone = $${i++}`); values.push(req.body.phone); }
    if (req.body.address !== undefined) { fields.push(`address = $${i++}`); values.push(req.body.address); }
    if (req.body.twoFactorEnabled !== undefined) { fields.push(`two_factor_enabled = $${i++}`); values.push(req.body.twoFactorEnabled); }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });

    values.push(req.user.userId);
    const result = await pool.query(
      `UPDATE users SET ${fields.join(", ")} WHERE id = $${i} RETURNING ${PUBLIC_USER_FIELDS}`,
      values
    );
    return res.json(result.rows[0]);
  }
);

router.get("/users/me/access-log", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT ip_address, created_at FROM access_log WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10`,
    [req.user.userId]
  );
  return res.json(result.rows);
});

router.get(
  "/users",
  requireAuth,
  requireAdmin,
  [query("search").optional().trim().escape()],
  handleValidation,
  async (req, res) => {
    const search = req.query.search;
    const result = search
      ? await pool.query(
          `SELECT ${PUBLIC_USER_FIELDS} FROM users
           WHERE first_name ILIKE $1 OR last_name ILIKE $1 OR email ILIKE $1
           ORDER BY created_at DESC`,
          [`%${search}%`]
        )
      : await pool.query(`SELECT ${PUBLIC_USER_FIELDS} FROM users ORDER BY created_at DESC`);
    return res.json(result.rows);
  }
);

router.patch(
  "/users/:id",
  requireAuth,
  requireAdmin,
  [
    param("id").isUUID(),
    body("balance").optional().isFloat({ min: 0 }),
    body("available").optional().isFloat({ min: 0 }),
    body("verificationLevel").optional().isIn(["Pendiente", "En Revisión", "Verificado"]),
    body("accountStatus").optional().isIn(["Activa", "En Revisión", "Suspendida"]),
    body("phone").optional().trim().isLength({ max: 30 }).escape(),
    body("address").optional().trim().isLength({ max: 255 }).escape(),
  ],
  handleValidation,
  async (req, res) => {
    const map = {
      balance: "balance", available: "available", verificationLevel: "verification_level",
      accountStatus: "account_status", phone: "phone", address: "address",
    };
    const fields = [];
    const values = [];
    let i = 1;
    for (const [key, column] of Object.entries(map)) {
      if (req.body[key] !== undefined) { fields.push(`${column} = $${i++}`); values.push(req.body[key]); }
    }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });

    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE users SET ${fields.join(", ")} WHERE id = $${i} RETURNING ${PUBLIC_USER_FIELDS}`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });
    return res.json(result.rows[0]);
  }
);

router.post(
  "/users/:id/adjust-funds",
  requireAuth,
  requireAdmin,
  [param("id").isUUID(), body("amount").isFloat({ min: 0.01 }), body("direction").isIn(["credit", "debit"])],
  handleValidation,
  async (req, res) => {
    const { amount, direction } = req.body;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const delta = direction === "credit" ? amount : -amount;
      const updated = await client.query(
        `UPDATE users SET balance = balance + $1, available = available + $1 WHERE id = $2 RETURNING ${PUBLIC_USER_FIELDS}`,
        [delta, req.params.id]
      );
      if (updated.rows.length === 0) throw new Error("NOT_FOUND");

      await client.query(
        `INSERT INTO transactions (user_id, type, amount, label, category, status)
         VALUES ($1, $2, $3, $4, 'Ajuste', 'completed')`,
        [req.params.id, direction, amount, direction === "credit" ? "Crédito agregado por la administración" : "Débito aplicado por la administración"]
      );
      await client.query("COMMIT");
      return res.json(updated.rows[0]);
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.message === "NOT_FOUND") return res.status(404).json({ error: "Usuario no encontrado" });
      throw err;
    } finally {
      client.release();
    }
  }
);

module.exports = router;

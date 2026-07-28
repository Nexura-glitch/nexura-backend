const express = require("express");
const { body, param } = require("express-validator");
const pool = require("./db");
const { requireAuth, requireAdmin, handleValidation } = require("./middleware");

const router = express.Router();
const VALID_NOTIF_TYPES = ["transaction", "transfer", "validation", "refusal", "account", "security"];
const VALID_DOC_CATEGORIES = ["Contratos", "Comprobantes", "Recibos", "Formularios"];

router.get("/notifications/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.userId]);
  return res.json(result.rows);
});

router.patch("/notifications/:id/read", requireAuth, [param("id").isUUID()], handleValidation, async (req, res) => {
  const result = await pool.query(
    `UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2 RETURNING *`,
    [req.params.id, req.user.userId]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Notificación no encontrada" });
  return res.json(result.rows[0]);
});

router.patch("/notifications/me/read-all", requireAuth, async (req, res) => {
  await pool.query(`UPDATE notifications SET is_read = TRUE WHERE user_id = $1`, [req.user.userId]);
  return res.status(204).send();
});

router.get("/notifications", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.query;
  const result = userId
    ? await pool.query(`SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC`, [userId])
    : await pool.query(`SELECT * FROM notifications ORDER BY created_at DESC`);
  return res.json(result.rows);
});

router.post(
  "/notifications",
  requireAuth,
  requireAdmin,
  [body("userId").isUUID(), body("type").isIn(VALID_NOTIF_TYPES), body("title").trim().isLength({ min: 1, max: 150 }).escape(), body("message").trim().isLength({ min: 1, max: 500 }).escape()],
  handleValidation,
  async (req, res) => {
    const { userId, type, title, message } = req.body;
    const result = await pool.query(`INSERT INTO notifications (user_id, type, title, message) VALUES ($1,$2,$3,$4) RETURNING *`, [userId, type, title, message]);
    return res.status(201).json(result.rows[0]);
  }
);

router.patch(
  "/notifications/:id",
  requireAuth,
  requireAdmin,
  [param("id").isUUID(), body("type").optional().isIn(VALID_NOTIF_TYPES), body("title").optional().trim().isLength({ min: 1, max: 150 }).escape(), body("message").optional().trim().isLength({ min: 1, max: 500 }).escape()],
  handleValidation,
  async (req, res) => {
    const fields = [];
    const values = [];
    let i = 1;
    for (const key of ["type", "title", "message"]) {
      if (req.body[key] !== undefined) { fields.push(`${key} = $${i++}`); values.push(req.body[key]); }
    }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });
    values.push(req.params.id);
    const result = await pool.query(`UPDATE notifications SET ${fields.join(", ")} WHERE id = $${i} RETURNING *`, values);
    if (result.rows.length === 0) return res.status(404).json({ error: "Notificación no encontrada" });
    return res.json(result.rows[0]);
  }
);

router.delete("/notifications/:id", requireAuth, requireAdmin, [param("id").isUUID()], handleValidation, async (req, res) => {
  await pool.query(`DELETE FROM notifications WHERE id = $1`, [req.params.id]);
  return res.status(204).send();
});

router.get("/documents/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM documents WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.userId]);
  return res.json(result.rows);
});

router.get("/documents", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.query;
  const result = userId
    ? await pool.query(`SELECT * FROM documents WHERE user_id = $1 ORDER BY created_at DESC`, [userId])
    : await pool.query(`SELECT * FROM documents ORDER BY created_at DESC`);
  return res.json(result.rows);
});

router.post(
  "/documents",
  requireAuth,
  requireAdmin,
  [body("userId").isUUID(), body("documentType").isIn(VALID_DOC_CATEGORIES), body("title").trim().isLength({ min: 1, max: 200 }).escape(), body("fileUrl").optional().trim().isURL()],
  handleValidation,
  async (req, res) => {
    const { userId, documentType, title, fileUrl } = req.body;
    const result = await pool.query(`INSERT INTO documents (user_id, document_type, title, file_url) VALUES ($1,$2,$3,$4) RETURNING *`, [userId, documentType, title, fileUrl || null]);
    await pool.query(`INSERT INTO notifications (user_id, type, title, message) VALUES ($1, 'account', 'Nuevo documento disponible', $2)`, [userId, `Se ha añadido un nuevo documento: "${title}".`]);
    return res.status(201).json(result.rows[0]);
  }
);

router.delete("/documents/:id", requireAuth, requireAdmin, [param("id").isUUID()], handleValidation, async (req, res) => {
  await pool.query(`DELETE FROM documents WHERE id = $1`, [req.params.id]);
  return res.status(204).send();
});

router.get("/beneficiaries/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM beneficiaries WHERE user_id = $1 ORDER BY name`, [req.user.userId]);
  return res.json(result.rows);
});

router.post(
  "/beneficiaries/me",
  requireAuth,
  [body("name").trim().isLength({ min: 1, max: 150 }).escape(), body("accountNumber").trim().isLength({ min: 4, max: 30 }).escape(), body("bank").optional().trim().isLength({ max: 150 }).escape(), body("accountType").optional().isIn(["Cuenta Corriente", "Cuenta de Ahorros"])],
  handleValidation,
  async (req, res) => {
    const { name, accountNumber, bank, accountType } = req.body;
    const result = await pool.query(
      `INSERT INTO beneficiaries (user_id, name, account_number, bank, account_type) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.userId, name, accountNumber, bank || null, accountType || "Cuenta Corriente"]
    );
    return res.status(201).json(result.rows[0]);
  }
);

router.patch(
  "/beneficiaries/:id",
  requireAuth,
  [param("id").isUUID(), body("name").optional().trim().isLength({ min: 1, max: 150 }).escape(), body("accountNumber").optional().trim().isLength({ min: 4, max: 30 }).escape(), body("bank").optional().trim().isLength({ max: 150 }).escape(), body("accountType").optional().isIn(["Cuenta Corriente", "Cuenta de Ahorros"])],
  handleValidation,
  async (req, res) => {
    const map = { name: "name", accountNumber: "account_number", bank: "bank", accountType: "account_type" };
    const fields = [];
    const values = [];
    let i = 1;
    for (const [key, column] of Object.entries(map)) {
      if (req.body[key] !== undefined) { fields.push(`${column} = $${i++}`); values.push(req.body[key]); }
    }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });
    values.push(req.params.id, req.user.userId);
    const result = await pool.query(`UPDATE beneficiaries SET ${fields.join(", ")} WHERE id = $${i} AND user_id = $${i + 1} RETURNING *`, values);
    if (result.rows.length === 0) return res.status(404).json({ error: "Beneficiario no encontrado" });
    return res.json(result.rows[0]);
  }
);

router.delete("/beneficiaries/:id", requireAuth, [param("id").isUUID()], handleValidation, async (req, res) => {
  const result = await pool.query(`DELETE FROM beneficiaries WHERE id = $1 AND user_id = $2 RETURNING id`, [req.params.id, req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Beneficiario no encontrado" });
  return res.status(204).send();
});

router.get("/stats/overview", requireAuth, requireAdmin, async (req, res) => {
  const [users, transfers, transactions, balance] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS count FROM users`),
    pool.query(`SELECT COUNT(*)::int AS count, COALESCE(SUM(amount), 0) AS volume FROM transfers`),
    pool.query(`SELECT COUNT(*)::int AS count FROM transactions`),
    pool.query(`SELECT COALESCE(SUM(balance), 0) AS total FROM users`),
  ]);
  return res.json({
    userCount: users.rows[0].count,
    transferCount: transfers.rows[0].count,
    totalVolume: Number(transfers.rows[0].volume),
    transactionCount: transactions.rows[0].count,
    totalBalance: Number(balance.rows[0].total),
  });
});

module.exports = router;

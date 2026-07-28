const express = require("express");
const { body, param } = require("express-validator");
const pool = require("./db");
const { requireAuth, requireAdmin, handleValidation } = require("./middleware");

const router = express.Router();
const VALID_STATUSES = ["pending", "review", "verified", "processing", "transferred", "completed", "cancelled"];

function generateReference() {
  const part = () => Math.random().toString(36).slice(2, 6).toUpperCase();
  const now = new Date();
  const y = String(now.getFullYear()).slice(2);
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  return `NX-${y}${m}${d}-${part()}${part()}`;
}
function generateCardNumber() {
  const part = () => String(Math.floor(1000 + Math.random() * 9000));
  return `${part()}${part()}${part()}${part()}`;
}
function defaultExpiry() {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 4);
  return d.toISOString().slice(0, 10);
}

router.get("/transactions/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.userId]);
  return res.json(result.rows);
});

router.get("/transactions", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.query;
  const result = userId
    ? await pool.query(`SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC`, [userId])
    : await pool.query(`SELECT * FROM transactions ORDER BY created_at DESC`);
  return res.json(result.rows);
});

router.post(
  "/transactions",
  requireAuth,
  requireAdmin,
  [
    body("userId").isUUID(),
    body("type").isIn(["credit", "debit"]),
    body("amount").isFloat({ min: 0.01 }),
    body("label").trim().isLength({ min: 1, max: 255 }).escape(),
    body("category").optional().trim().isLength({ max: 100 }).escape(),
  ],
  handleValidation,
  async (req, res) => {
    const { userId, type, amount, label, category } = req.body;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const delta = type === "credit" ? amount : -amount;
      const userUpdate = await client.query(
        `UPDATE users SET balance = balance + $1, available = available + $1 WHERE id = $2 RETURNING id`,
        [delta, userId]
      );
      if (userUpdate.rows.length === 0) throw new Error("NOT_FOUND");

      const txn = await client.query(
        `INSERT INTO transactions (user_id, type, amount, label, category, status, reference)
         VALUES ($1,$2,$3,$4,$5,'completed',$6) RETURNING *`,
        [userId, type, amount, label, category || null, generateReference()]
      );
      await client.query("COMMIT");
      return res.status(201).json(txn.rows[0]);
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.message === "NOT_FOUND") return res.status(404).json({ error: "Usuario no encontrado" });
      throw err;
    } finally {
      client.release();
    }
  }
);

router.delete("/transactions/:id", requireAuth, requireAdmin, [param("id").isUUID()], handleValidation, async (req, res) => {
  await pool.query(`DELETE FROM transactions WHERE id = $1`, [req.params.id]);
  return res.status(204).send();
});

router.get("/transfers/me", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM transfers WHERE sender_id = $1 ORDER BY created_at DESC`, [req.user.userId]);
  return res.json(result.rows);
});

router.post(
  "/transfers/me",
  requireAuth,
  [
    body("beneficiaryName").trim().isLength({ min: 1, max: 150 }).escape(),
    body("receiverAccount").trim().isLength({ min: 4, max: 30 }).escape(),
    body("receiverBank").optional().trim().isLength({ max: 150 }).escape(),
    body("accountType").optional().isIn(["Cuenta Corriente", "Cuenta de Ahorros"]),
    body("amount").isFloat({ min: 0.01 }),
    body("transferType").isIn(["interna", "programada"]),
    body("scheduledDate").optional({ nullable: true }).isISO8601(),
    body("note").optional().trim().isLength({ max: 255 }).escape(),
  ],
  handleValidation,
  async (req, res) => {
    const { beneficiaryName, receiverAccount, receiverBank, accountType, amount, transferType, scheduledDate, note } = req.body;
    const userResult = await pool.query("SELECT available FROM users WHERE id = $1", [req.user.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });
    if (Number(userResult.rows[0].available) < Number(amount)) {
      return res.status(400).json({ error: "Saldo disponible insuficiente" });
    }

    const result = await pool.query(
      `INSERT INTO transfers
        (sender_id, beneficiary_name, receiver_account, receiver_bank, account_type, amount, transfer_type, scheduled_date, note, reference, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending') RETURNING *`,
      [req.user.userId, beneficiaryName, receiverAccount, receiverBank || null, accountType || "Cuenta Corriente",
       amount, transferType, scheduledDate || null, note || null, generateReference()]
    );

    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, 'transfer', 'Solicitud de transferencia recibida', $2)`,
      [req.user.userId, `Su transferencia a ${beneficiaryName} (${amount}) fue registrada con la referencia ${result.rows[0].reference}.`]
    );
    return res.status(201).json(result.rows[0]);
  }
);

router.get("/transfers", requireAuth, requireAdmin, async (req, res) => {
  const result = await pool.query(`SELECT * FROM transfers ORDER BY created_at DESC`);
  return res.json(result.rows);
});

router.post(
  "/transfers",
  requireAuth,
  requireAdmin,
  [
    body("userId").isUUID(),
    body("beneficiaryName").trim().isLength({ min: 1, max: 150 }).escape(),
    body("receiverAccount").trim().isLength({ min: 4, max: 30 }).escape(),
    body("amount").isFloat({ min: 0.01 }),
    body("status").isIn(VALID_STATUSES),
  ],
  handleValidation,
  async (req, res) => {
    const { userId, beneficiaryName, receiverAccount, receiverBank, accountType, amount, status, note } = req.body;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const reference = generateReference();
      const transfer = await client.query(
        `INSERT INTO transfers (sender_id, beneficiary_name, receiver_account, receiver_bank, account_type, amount, status, note, reference)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [userId, beneficiaryName, receiverAccount, receiverBank || null, accountType || "Cuenta Corriente", amount, status, note || null, reference]
      );

      if (status === "completed") {
        const userUpdate = await client.query(
          `UPDATE users SET balance = balance - $1, available = available - $1 WHERE id = $2 AND available >= $1 RETURNING id`,
          [amount, userId]
        );
        if (userUpdate.rows.length === 0) throw new Error("INSUFFICIENT_FUNDS");
        await client.query(
          `INSERT INTO transactions (user_id, type, amount, label, category, status, reference)
           VALUES ($1, 'debit', $2, $3, 'Transferencia', 'completed', $4)`,
          [userId, amount, `Transferencia a ${beneficiaryName}`, reference]
        );
      }
      await client.query("COMMIT");
      return res.status(201).json(transfer.rows[0]);
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.message === "INSUFFICIENT_FUNDS") return res.status(400).json({ error: "Saldo disponible insuficiente" });
      throw err;
    } finally {
      client.release();
    }
  }
);

router.patch(
  "/transfers/:id/status",
  requireAuth,
  requireAdmin,
  [param("id").isUUID(), body("status").isIn(VALID_STATUSES)],
  handleValidation,
  async (req, res) => {
    const { status } = req.body;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(`SELECT * FROM transfers WHERE id = $1 FOR UPDATE`, [req.params.id]);
      if (current.rows.length === 0) throw new Error("NOT_FOUND");
      const transfer = current.rows[0];

      const updated = await client.query(`UPDATE transfers SET status = $1 WHERE id = $2 RETURNING *`, [status, req.params.id]);

      if (transfer.status !== "completed" && status === "completed") {
        const userUpdate = await client.query(
          `UPDATE users SET balance = balance - $1, available = available - $1 WHERE id = $2 AND available >= $1 RETURNING id`,
          [transfer.amount, transfer.sender_id]
        );
        if (userUpdate.rows.length === 0) throw new Error("INSUFFICIENT_FUNDS");
        await client.query(
          `INSERT INTO transactions (user_id, type, amount, label, category, status, reference)
           VALUES ($1, 'debit', $2, $3, 'Transferencia', 'completed', $4)`,
          [transfer.sender_id, transfer.amount, `Transferencia a ${transfer.beneficiary_name}`, transfer.reference]
        );
      }

      await client.query(
        `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
        [transfer.sender_id, status === "cancelled" ? "refusal" : "validation", `Estado actualizado: ${status}`,
         `Su transferencia ${transfer.reference} a ${transfer.beneficiary_name} ahora está en estado "${status}".`]
      );

      await client.query("COMMIT");
      return res.json(updated.rows[0]);
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.message === "NOT_FOUND") return res.status(404).json({ error: "Transferencia no encontrada" });
      if (err.message === "INSUFFICIENT_FUNDS") return res.status(400).json({ error: "Saldo disponible insuficiente" });
      throw err;
    } finally {
      client.release();
    }
  }
);

router.get("/cards/me", requireAuth, async (req, res) => {
  let result = await pool.query(`SELECT * FROM cards WHERE user_id = $1 ORDER BY card_type`, [req.user.userId]);
  if (result.rows.length === 0) {
    await pool.query(
      `INSERT INTO cards (user_id, card_type, card_number, expiry_date, is_active, spend_limit)
       VALUES ($1, 'debito', $2, $3, TRUE, 1000), ($1, 'virtual', $4, $3, FALSE, 300)`,
      [req.user.userId, generateCardNumber(), defaultExpiry(), generateCardNumber()]
    );
    result = await pool.query(`SELECT * FROM cards WHERE user_id = $1 ORDER BY card_type`, [req.user.userId]);
  }
  const masked = result.rows.map((c) => ({ ...c, card_number: `•••• ${c.card_number.slice(-4)}` }));
  return res.json(masked);
});

router.post("/cards/:id/reveal", requireAuth, [param("id").isUUID()], handleValidation, async (req, res) => {
  const result = await pool.query(`SELECT card_number FROM cards WHERE id = $1 AND user_id = $2`, [req.params.id, req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Tarjeta no encontrada" });
  return res.json({ cardNumber: result.rows[0].card_number });
});

router.patch(
  "/cards/:id",
  requireAuth,
  [param("id").isUUID(), body("isActive").optional().isBoolean(), body("isFrozen").optional().isBoolean(), body("spendLimit").optional().isFloat({ min: 0 })],
  handleValidation,
  async (req, res) => {
    const fields = [];
    const values = [];
    let i = 1;
    if (req.body.isActive !== undefined) { fields.push(`is_active = $${i++}`); values.push(req.body.isActive); }
    if (req.body.isFrozen !== undefined) { fields.push(`is_frozen = $${i++}`); values.push(req.body.isFrozen); }
    if (req.body.spendLimit !== undefined) { fields.push(`spend_limit = $${i++}`); values.push(req.body.spendLimit); }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });
    values.push(req.params.id, req.user.userId);
    const result = await pool.query(
      `UPDATE cards SET ${fields.join(", ")} WHERE id = $${i} AND user_id = $${i + 1} RETURNING id, card_type, is_active, is_frozen, spend_limit, expiry_date`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Tarjeta no encontrada" });
    return res.json(result.rows[0]);
  }
);

router.get("/cards", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.query;
  const result = userId ? await pool.query(`SELECT * FROM cards WHERE user_id = $1`, [userId]) : await pool.query(`SELECT * FROM cards`);
  const masked = result.rows.map((c) => ({ ...c, card_number: `•••• ${c.card_number.slice(-4)}` }));
  return res.json(masked);
});

router.patch(
  "/cards/:id/admin",
  requireAuth,
  requireAdmin,
  [param("id").isUUID(), body("isActive").optional().isBoolean(), body("isFrozen").optional().isBoolean(), body("spendLimit").optional().isFloat({ min: 0 })],
  handleValidation,
  async (req, res) => {
    const fields = [];
    const values = [];
    let i = 1;
    if (req.body.isActive !== undefined) { fields.push(`is_active = $${i++}`); values.push(req.body.isActive); }
    if (req.body.isFrozen !== undefined) { fields.push(`is_frozen = $${i++}`); values.push(req.body.isFrozen); }
    if (req.body.spendLimit !== undefined) { fields.push(`spend_limit = $${i++}`); values.push(req.body.spendLimit); }
    if (fields.length === 0) return res.status(400).json({ error: "Nada que actualizar" });
    values.push(req.params.id);
    const result = await pool.query(`UPDATE cards SET ${fields.join(", ")} WHERE id = $${i} RETURNING *`, values);
    if (result.rows.length === 0) return res.status(404).json({ error: "Tarjeta no encontrada" });
    return res.json(result.rows[0]);
  }
);

module.exports = router;

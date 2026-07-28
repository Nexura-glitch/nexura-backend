const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { validationResult } = require("express-validator");

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Token de autenticación no proporcionado" });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Acceso restringido a administradores" });
  }
  return next();
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "8h",
  });
}

const apiLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiadas solicitudes. Intente de nuevo más tarde." },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiados intentos de inicio de sesión. Intente de nuevo en unos minutos." },
});

function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: "Datos inválidos", details: errors.array() });
  }
  return next();
}

module.exports = { requireAuth, requireAdmin, signToken, apiLimiter, loginLimiter, handleValidation };

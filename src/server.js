require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const { apiLimiter } = require("./middleware");
const routesAccount = require("./routes-account");
const routesMoney = require("./routes-money");
const routesExtra = require("./routes-extra");

const app = express();

app.use(helmet());

const allowedOrigins = (process.env.CORS_ORIGIN || "").split(",").map((o) => o.trim()).filter(Boolean);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Origen no permitido por la política CORS"));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "100kb" }));
app.use("/api", apiLimiter);

app.use("/api", routesAccount);
app.use("/api", routesMoney);
app.use("/api", routesExtra);

app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

app.use((req, res) => res.status(404).json({ error: "Ruta no encontrada" }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  if (err.message === "Origen no permitido por la política CORS") {
    return res.status(403).json({ error: err.message });
  }
  res.status(500).json({ error: "Error interno del servidor" });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Nexura API escuchando en el puerto ${PORT}`);
});

module.exports = app;

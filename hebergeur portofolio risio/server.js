require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

if (!process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD ||
    process.env.ADMIN_PASSWORD === "CHANGE_MOI_AVANT_DE_LANCER" ||
    !process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.startsWith("CHANGE_")) {
  console.error("Configure d'abord les identifiants et SESSION_SECRET dans .env");
  process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });

const db = new Database(path.join(__dirname, "data", "portfolio.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    visitor_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender TEXT NOT NULL CHECK(sender IN ('visitor', 'admin')),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id)
  );

  CREATE TABLE IF NOT EXISTS content (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    json TEXT NOT NULL
  );
`);

const initialContent = {
  name: "Risio",
  tagline: "Création web, Discord et Minecraft",
  description: "Je conçois des projets numériques, des expériences Minecraft et des outils Discord.",
  email: "risio.1contact@gmail.com",
  discord: "risioytb",
  availability: "Disponible selon mes disponibilités",
  services: [
    { name: "Configuration Discord simple", price: "5 €", description: "Mise en place des salons et rôles." },
    { name: "Configuration Discord complète", price: "15 €", description: "Organisation complète d'un serveur." },
    { name: "Bot Discord simple", price: "10 €", description: "Bot avec commandes personnalisées simples." },
    { name: "Bot Discord personnalisé", price: "25 €", description: "Fonctionnalités adaptées à ton projet." },
    { name: "Configuration serveur Minecraft", price: "15 €", description: "Configuration et permissions." },
    { name: "Serveur Minecraft complet", price: "35 €", description: "Mise en place d'un serveur complet." },
    { name: "Plugin Minecraft simple", price: "10 €", description: "Plugin avec fonctionnalité ciblée." },
    { name: "Plugin Minecraft personnalisé", price: "25 €", description: "Plugin adapté à un besoin précis." },
    { name: "Site vitrine", price: "20 €", description: "Site web de présentation." },
    { name: "Portfolio professionnel", price: "25 €", description: "Portfolio personnalisé." },
    { name: "Petite application web", price: "30 €", description: "Application web simple." }
  ],
  projects: [
    { name: "ChunkWars", category: "Minecraft", description: "Concept de mini-jeu en équipes autour de noyaux et d'îles." },
    { name: "RisioBot", category: "Discord", description: "Projet de bot Discord avec modération, tickets et outils communautaires." },
    { name: "Risio IA", category: "Web", description: "Projet d'assistant orienté création et développement." },
    { name: "Ender Studio", category: "Minecraft", description: "Concept de services autour des serveurs et créations Minecraft." }
  ],
  skills: ["HTML", "CSS", "JavaScript", "Node.js", "Discord.js", "Minecraft"]
};

const savedContent = db.prepare("SELECT id FROM content WHERE id = 1").get();
if (!savedContent) {
  db.prepare("INSERT INTO content (id, json) VALUES (1, ?)").run(
    JSON.stringify(initialContent)
  );
}

const SQLiteStore = SQLiteStoreFactory(session);

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: path.join(__dirname, "data")
  }),
  name: "risio.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Trop de tentatives. Réessaie dans quelques minutes." }
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const adminPasswordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: "Connexion administrateur requise." });
  }
  next();
}

function cleanText(value, max = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

function getContent() {
  return JSON.parse(db.prepare("SELECT json FROM content WHERE id = 1").get().json);
}

function getConversationByToken(token) {
  return db.prepare("SELECT * FROM conversations WHERE token = ?").get(token);
}

app.get("/api/content", (req, res) => {
  res.json(getContent());
});

// Création d'une conversation et premier message
app.post("/api/chat", chatLimiter, (req, res) => {
  const name = cleanText(req.body.name, 50);
  const body = cleanText(req.body.message, 2000);

  if (!name || !body) {
    return res.status(400).json({ error: "Pseudo et message obligatoires." });
  }

  const token = crypto.randomBytes(32).toString("hex");

  const result = db.prepare(
    "INSERT INTO conversations (token, visitor_name) VALUES (?, ?)"
  ).run(token, name);

  db.prepare(
    "INSERT INTO messages (conversation_id, sender, body) VALUES (?, 'visitor', ?)"
  ).run(result.lastInsertRowid, body);

  res.status(201).json({ token });
});

// Récupérer une conversation avec son lien privé
app.get("/api/chat/:token", (req, res) => {
  const conversation = getConversationByToken(req.params.token);
  if (!conversation) return res.status(404).json({ error: "Conversation introuvable." });

  const messages = db.prepare(
    "SELECT sender, body, created_at FROM messages WHERE conversation_id = ? ORDER BY id"
  ).all(conversation.id);

  res.json({ name: conversation.visitor_name, messages });
});

// Ajouter un message visiteur
app.post("/api/chat/:token", chatLimiter, (req, res) => {
  const conversation = getConversationByToken(req.params.token);
  if (!conversation) return res.status(404).json({ error: "Conversation introuvable." });

  const body = cleanText(req.body.message, 2000);
  if (!body) return res.status(400).json({ error: "Message vide." });

  db.prepare(
    "INSERT INTO messages (conversation_id, sender, body) VALUES (?, 'visitor', ?)"
  ).run(conversation.id, body);

  res.status(201).json({ ok: true });
});

// Connexion administrateur
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const username = cleanText(req.body.username, 80);
  const password = typeof req.body.password === "string" ? req.body.password : "";

  const validUser = username === process.env.ADMIN_USERNAME;
  const validPassword = await bcrypt.compare(password, adminPasswordHash);

  if (!validUser || !validPassword) {
    return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: "Erreur de session." });
    req.session.isAdmin = true;
    res.json({ ok: true });
  });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("risio.sid");
    res.json({ ok: true });
  });
});

app.get("/api/admin/me", (req, res) => {
  res.json({ authenticated: Boolean(req.session.isAdmin) });
});

// Liste des conversations
app.get("/api/admin/conversations", requireAdmin, (req, res) => {
  const conversations = db.prepare(`
    SELECT c.id, c.visitor_name, c.created_at,
      (SELECT body FROM messages WHERE conversation_id = c.id ORDER BY id DESC LIMIT 1) AS last_message,
      (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender = 'visitor') AS visitor_messages
    FROM conversations c
    ORDER BY c.id DESC
  `).all();

  res.json(conversations);
});

// Lire une conversation
app.get("/api/admin/conversations/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const conversation = db.prepare(
    "SELECT id, visitor_name FROM conversations WHERE id = ?"
  ).get(id);

  if (!conversation) return res.status(404).json({ error: "Introuvable." });

  const messages = db.prepare(
    "SELECT sender, body, created_at FROM messages WHERE conversation_id = ? ORDER BY id"
  ).all(id);

  res.json({ conversation, messages });
});

// Répondre à un visiteur
app.post("/api/admin/conversations/:id/reply", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const conversation = db.prepare("SELECT id FROM conversations WHERE id = ?").get(id);
  const body = cleanText(req.body.message, 2000);

  if (!conversation) return res.status(404).json({ error: "Conversation introuvable." });
  if (!body) return res.status(400).json({ error: "Réponse vide." });

  db.prepare(
    "INSERT INTO messages (conversation_id, sender, body) VALUES (?, 'admin', ?)"
  ).run(id, body);

  res.status(201).json({ ok: true });
});

// Supprimer une conversation
app.delete("/api/admin/conversations/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("DELETE FROM messages WHERE conversation_id = ?").run(id);
  db.prepare("DELETE FROM conversations WHERE id = ?").run(id);
  res.json({ ok: true });
});

// Modifier le contenu du portfolio depuis l'administration
app.put("/api/admin/content", requireAdmin, (req, res) => {
  const content = req.body.content;

  if (!content || typeof content !== "object" || Array.isArray(content)) {
    return res.status(400).json({ error: "Contenu invalide." });
  }

  const json = JSON.stringify(content);
  if (json.length > 50000) {
    return res.status(400).json({ error: "Contenu trop volumineux." });
  }

  db.prepare("UPDATE content SET json = ? WHERE id = 1").run(json);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Portfolio Risio lancé : http://localhost:${PORT}`);
  console.log(`Administration : http://localhost:${PORT}/admin`);
});
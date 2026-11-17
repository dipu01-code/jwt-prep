require("dotenv/config");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { PrismaPg } = require("@prisma/adapter-pg");

if (!process.env.JWTSECRET) throw new Error("JWTSECRET is not set");

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});
const app = express();
app.use(express.json());

const normalizeEmail = (email) => email.trim().toLowerCase();

const signToken = (user) =>
  jwt.sign({ id: user.id, email: user.email }, process.env.JWTSECRET, {
    expiresIn: "1h",
    jwtid: crypto.randomUUID(),
  });

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }
  try {
    req.user = jwt.verify(token, process.env.JWTSECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.post("/signup", async (req, res) => {
  const { email, password, name } = req.body ?? {};
  if (typeof email !== "string" || !email.trim() || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }
  if (name !== undefined && typeof name !== "string") {
    return res.status(400).json({ error: "Name must be a string" });
  }

  const normalized = normalizeEmail(email);
  if (await prisma.user.findUnique({ where: { email: normalized } })) {
    return res.status(409).json({ error: "Email already registered" });
  }

  try {
    const user = await prisma.user.create({
      data: { email: normalized, password: await bcrypt.hash(password, 10), name },
      select: { id: true, email: true, name: true, createdAt: true },
    });
    res.status(201).json({ user, token: signToken(user) });
  } catch (err) {
    // two signups for the same email can both pass the check above
    if (err.code === "P2002") return res.status(409).json({ error: "Email already registered" });
    throw err;
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = await prisma.user.findUnique({ where: { email: normalizeEmail(email) } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  res.json({
    user: { id: user.id, email: user.email, name: user.name },
    token: signToken(user),
  });
});

app.get("/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { id: true, email: true, name: true, createdAt: true },
  });
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { email: true, name: true },
  });
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ message: `Welcome, ${user.name || user.email}!` });
});

// malformed JSON bodies and anything unexpected
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON" });
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Listening on http://localhost:${port}`));
}

module.exports = { app, prisma };

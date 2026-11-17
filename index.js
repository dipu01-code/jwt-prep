require("dotenv/config"); // loads the values from .env into process.env

const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { PrismaPg } = require("@prisma/adapter-pg");

const JWTSECRET = process.env.JWTSECRET;
if (!JWTSECRET) {
  throw new Error("JWTSECRET is not set in .env");
}

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter: adapter });

const app = express();
app.use(express.json());


function normalizeEmail(email) {
  return email.trim().toLowerCase();
}


function createToken(user) {
  const payload = { id: user.id, email: user.email };
  const options = { expiresIn: "1h", jwtid: crypto.randomUUID() };
  return jwt.sign(payload, JWTSECRET, options);
}




function requireAuth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token is missing" });
  }

  const token = header.split(" ")[1];

  try {

    const decoded = jwt.verify(token, JWTSECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token is invalid or expired" });
  }
}


app.post("/signup", async function (req, res) {
  try {
    const body = req.body || {};
    const email = body.email;
    const password = body.password;
    const name = body.name;


    if (typeof email !== "string" || email.trim() === "") {
      return res.status(400).json({ error: "Email is required" });
    }
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    if (name !== undefined && typeof name !== "string") {
      return res.status(400).json({ error: "Name must be a string" });
    }

    const cleanEmail = normalizeEmail(email);
    const existingUser = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { email: cleanEmail, password: hashedPassword, name: name },
    });

    const token = createToken(newUser);
    return res.status(201).json({
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        createdAt: newUser.createdAt,
      },
      token: token,
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(error);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/login", async function (req, res) {
  try {
    const body = req.body || {};
    const email = body.email;
    const password = body.password;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await prisma.user.findUnique({
      where: { email: normalizeEmail(email) },
    });


    let passwordIsCorrect = false;
    if (user) {
      passwordIsCorrect = await bcrypt.compare(password, user.password);
    }
    if (!user || !passwordIsCorrect) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = createToken(user);
    return res.status(200).json({
      user: { id: user.id, email: user.email, name: user.name },
      token: token,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Something went wrong" });
  }
});


app.get("/me", requireAuth, async function (req, res) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, name: true, createdAt: true },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.status(200).json({ user: user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

app.get("/dashboard", requireAuth, async function (req, res) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { email: true, name: true },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let displayName = user.email;
    if (user.name) {
      displayName = user.name;
    }
    return res.status(200).json({ message: "Welcome, " + displayName + "!" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

app.use(function (error, req, res, next) {
  return res.status(400).json({ error: "Invalid JSON" });
});



if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, function () {
    console.log("Server running on http://localhost:" + port);
  });
}

module.exports = { app, prisma };

// =======================================================
// EARN24 SG - Backend Server (Render + MongoDB + InfinityFree Frontend)
// =======================================================

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");

const app = express();

// ------------------- Middleware -------------------
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(mongoSanitize());

// ------------------- Security Config -------------------
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 200,
  message: "Too many requests, please try again later.",
});
app.use("/api", limiter);

// ------------------- MongoDB Connection -------------------
const dbURI = process.env.MONGO_URI;
mongoose
  .connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ------------------- Models -------------------
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  balanceUSDT: { type: Number, default: 0 },
  points: { type: Number, default: 0 },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  type: String, // earning, bonus, redeem, etc.
  amountUSDT: Number,
  description: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

// ------------------- Utils -------------------
const generateToken = (user) =>
  jwt.sign(
    { id: user._id, username: user.username, isAdmin: user.isAdmin },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || "7d" }
  );

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
};

// ------------------- Helper: Create Dev Admin -------------------
async function createDevAdmin() {
  const email = process.env.DEV_ADMIN_EMAIL;
  const password = process.env.DEV_ADMIN_PASSWORD;
  if (!email || !password) {
    console.warn("⚠️ DEV_ADMIN_EMAIL or DEV_ADMIN_PASSWORD missing in .env");
    return;
  }
  const exists = await User.findOne({ email });
  if (exists) {
    console.log("✅ Admin already exists.");
    return;
  }
  const hash = await bcrypt.hash(password, 10);
  const admin = new User({
    username: "Admin",
    email,
    password: hash,
    isAdmin: true,
  });
  await admin.save();
  console.log("👑 Dev admin created:", email);
}

// ------------------- Routes -------------------
app.get("/", (req, res) => res.send("EARN24 SG Backend is Live 🚀"));

// --- Register ---
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, referralCode } = req.body;
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists)
      return res.status(400).json({ message: "Username or Email already in use" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashed,
      referralCode: uuidv4().slice(0, 8),
    });

    // Referral
    if (referralCode) {
      const refUser = await User.findOne({ referralCode });
      if (refUser) {
        newUser.referredBy = refUser._id;
        refUser.points += parseInt(process.env.REFERRAL_POINTS || 50);
        await refUser.save();
        await Transaction.create({
          userId: refUser._id,
          type: "bonus",
          amountUSDT: 0,
          description: `Referral bonus from ${username}`,
        });
      }
    }

    // Welcome bonus
    newUser.balanceUSDT = parseFloat(process.env.WELCOME_BONUS_USDT || 1);
    await newUser.save();

    res.json({ message: "User registered successfully", referralCode: newUser.referralCode });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// --- Login ---
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid credentials" });

  const token = generateToken(user);
  res.json({
    token,
    user: {
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
      balanceUSDT: user.balanceUSDT,
      points: user.points,
    },
  });
});

// --- Get User Balance ---
app.get("/api/user/balance", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ balanceUSDT: user.balanceUSDT, points: user.points });
  } catch {
    res.status(500).json({ message: "Error fetching balance" });
  }
});

// --- Admin: Get Users ---
app.get("/api/admin/users", authenticate, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: "Admin only" });
  const users = await User.find().select("-password");
  res.json(users);
});

// --- Admin: Credit Reward ---
app.post("/api/admin/credit", authenticate, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: "Admin only" });
  const { userId, amountUSDT, description } = req.body;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: "User not found" });
  user.balanceUSDT += parseFloat(amountUSDT);
  await user.save();
  await Transaction.create({
    userId: user._id,
    type: "admin_credit",
    amountUSDT,
    description: description || "Admin credit",
  });
  res.json({ message: "User credited successfully" });
});

// --- Admin: View Transactions ---
app.get("/api/admin/transactions", authenticate, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: "Admin only" });
  const txs = await Transaction.find().populate("userId", "username email");
  res.json(txs);
});

// --- Currency Conversion ---
app.get("/api/currency/:to", async (req, res) => {
  try {
    const { to } = req.params;
    const resp = await axios.get(
      `https://api.exchangerate.host/latest?base=USD&symbols=${to}`
    );
    res.json(resp.data);
  } catch {
    res.status(500).json({ message: "Conversion error" });
  }
});

// ------------------- Server Init -------------------
app.listen(process.env.PORT || 3001, async () => {
  await createDevAdmin();
  console.log(`🚀 Server running on port ${process.env.PORT || 3001}`);
});

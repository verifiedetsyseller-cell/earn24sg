// server.js - earn24sg (updated: signup + referral + rewards + redeem + currency)
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid'); // for referral codes

const app = express();
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());

// rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many login attempts, please try again after 15 minutes.' });

// ---------- Config values (set these on Render Environment)
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;
const WELCOME_BONUS_USDT = parseFloat(process.env.WELCOME_BONUS_USDT) || 1.0; // amount in USDT
const REFERRAL_POINTS = parseInt(process.env.REFERRAL_POINTS) || 50; // points given to referrer
const POINTS_TO_USDT_RATE = parseFloat(process.env.POINTS_TO_USDT_RATE) || 100; // 100 points = 1 USDT

// ---------- MongoDB connection
const dbURI = process.env.MONGODB_URI;
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ Successfully connected to MongoDB database.'))
  .catch(err => console.error('❌ Database connection error:', err));

// ---------- Schemas & Models (extend your existing User with referral fields)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  balanceUSDT: { type: Number, default: 0 }, // store balance in USDT
  points: { type: Number, default: 0 }, // referral/points
  referralCode: { type: String, unique: true, index: true }, // user-specific referral code
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  registrationDate: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});
const User = mongoose.model('User', UserSchema);

// Transactions and other schemas (simple)
const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['earning','withdrawal','bonus','refund','redeem'], required: true },
  amountUSDT: { type: Number, required: true }, // USDT positive or negative
  description: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// ---------- Helpers
function generateReferralCode() {
  // short code: first 8 chars of uuid
  return uuidv4().split('-')[0];
}

function mapCountryToCurrency(countryCode) {
  // simple mapping; expand as needed
  if (!countryCode) return 'USD';
  const cc = countryCode.toUpperCase();
  if (cc === 'SG' || cc === 'SGP') return 'SGD';
  if (cc === 'US' || cc === 'USA') return 'USD';
  if (['GB','FR','DE','ES','IT','NL','BE','LU','IE','AT'].includes(cc)) return 'EUR';
  return 'USD';
}

async function getCurrencyConversion(from = 'USD', to = 'USD') {
  // uses exchangerate.host (no API key) - runtime call
  try {
    const url = `https://api.exchangerate.host/latest?base=${encodeURIComponent(from)}&symbols=${encodeURIComponent(to)}`;
    const r = await axios.get(url, { timeout: 8000 });
    const rate = r.data?.rates?.[to];
    return rate || 1;
  } catch (err) {
    console.error('Currency conversion error:', err.message || err);
    return 1;
  }
}

// ---------- Auth middleware
function generateToken(user) {
  return jwt.sign({ userId: user._id, username: user.username, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
}
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user; next();
  });
};

// ---------- Routes

// health
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// register (enhanced with referral)
app.post('/api/register', [
  body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { username, email, password, referralCode } = req.body;

    // check existing
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ message: existing.email === email ? 'Account with this email exists.' : 'Username taken.' });

    const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
    const hashed = await bcrypt.hash(password, salt);

    // create user
    const newUser = new User({
      username, email, password: hashed,
      referralCode: generateReferralCode()
    });

    // handle referral
    if (referralCode) {
      const refUser = await User.findOne({ referralCode });
      if (refUser) {
        newUser.referredBy = refUser._id;
        // credit referrer points
        refUser.points = (refUser.points || 0) + REFERRAL_POINTS;
        await refUser.save();
        // record transaction for referrer (optional as points)
        await Transaction.create({ userId: refUser._id, type: 'bonus', amountUSDT: 0, description: `Referral points (${REFERRAL_POINTS}) from ${username}` });
      }
    }

    await newUser.save();

    // welcome bonus in USDT
    if (WELCOME_BONUS_USDT > 0) {
      newUser.balanceUSDT = (newUser.balanceUSDT || 0) + WELCOME_BONUS_USDT;
      await newUser.save();
      await Transaction.create({ userId: newUser._id, type: 'bonus', amountUSDT: WELCOME_BONUS_USDT, description: 'Welcome bonus' });
    }

    res.status(201).json({ message: 'User registered successfully', referralCode: newUser.referralCode });
  } catch (err) {
    console.error('Registration Error:', err);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

// login
app.post('/api/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.isActive) return res.status(400).json({ message: 'Invalid credentials or account inactive.' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials.' });
    user.lastLogin = new Date(); await user.save();
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, username: user.username, email: user.email, balanceUSDT: user.balanceUSDT, points: user.points } });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// complete a task -> credit USDT reward and optionally points
app.post('/api/tasks/complete', authenticateToken, [
  body('rewardUSDT').isFloat({ min: 0 })
], async (req, res) => {
  try {
    const { rewardUSDT } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    user.balanceUSDT = (user.balanceUSDT || 0) + Number(rewardUSDT);
    // optionally give points for completing tasks
    user.points = (user.points || 0) + Math.round(rewardUSDT * 10); // example: 1 USDT -> 10 points
    await user.save();
    await Transaction.create({ userId: user._id, type: 'earning', amountUSDT: rewardUSDT, description: 'Task completed reward' });
    res.json({ message: 'Task credited', balanceUSDT: user.balanceUSDT, points: user.points });
  } catch (err) {
    console.error('Task Error:', err);
    res.status(500).json({ message: 'Error crediting task.' });
  }
});

// redeem points -> convert to USDT and add to balance
app.post('/api/points/redeem', authenticateToken, [
  body('points').isInt({ min: 1 })
], async (req, res) => {
  try {
    const { points } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if ((user.points || 0) < points) return res.status(400).json({ message: 'Not enough points.' });

    const usdtValue = (points / POINTS_TO_USDT_RATE); // e.g., 100 points = 1 USDT
    user.points -= points;
    user.balanceUSDT = (user.balanceUSDT || 0) + usdtValue;
    await user.save();
    await Transaction.create({ userId: user._id, type: 'redeem', amountUSDT: usdtValue, description: `Redeemed ${points} points -> ${usdtValue} USDT` });
    res.json({ message: 'Redeem successful', balanceUSDT: user.balanceUSDT, points: user.points });
  } catch (err) {
    console.error('Redeem Error:', err);
    res.status(500).json({ message: 'Error redeeming points.' });
  }
});

// get user balance in local currency (detect IP)
app.get('/api/user/balance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    // detect currency by request IP (use x-forwarded-for if behind proxy)
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    let countryCode = null;
    try {
      const ipinfo = await axios.get(`http://ip-api.com/json/${ip}`);
      if (ipinfo.data && ipinfo.data.countryCode) countryCode = ipinfo.data.countryCode;
    } catch (e) {
      console.warn('IP lookup failed, default to USD');
    }
    const localCurrency = mapCountryToCurrency(countryCode);
    const rate = await getCurrencyConversion('USD', localCurrency); // USDT ~ USD
    const localBalance = (user.balanceUSDT || 0) * rate;
    res.json({ balanceUSDT: user.balanceUSDT || 0, localCurrency, localBalance });
  } catch (err) {
    console.error('Balance Error:', err);
    res.status(500).json({ message: 'Error fetching balance.' });
  }
});

// simple admin endpoint to credit points (protected)
app.post('/api/admin/credit', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin required.' });
    const { userId, points = 0, usdt = 0, reason = 'admin credit' } = req.body;
    const u = await User.findById(userId);
    if (!u) return res.status(404).json({ message: 'User not found.' });
    u.points += Number(points);
    u.balanceUSDT += Number(usdt);
    await u.save();
    await Transaction.create({ userId: u._id, type: 'bonus', amountUSDT: Number(usdt), description: `Admin credit: ${reason}` });
    res.json({ message: 'Credited', user: { id: u._id, points: u.points, balanceUSDT: u.balanceUSDT } });
  } catch (err) {
    console.error('Admin credit error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Register simple root (helpful)
app.get('/', (req, res) => res.send('EARN24 SG API is running'));

// ---------- Start
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Backend server for EARN24 SG is running on http://localhost:${PORT}`);
});

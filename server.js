// server.js - Secure Backend for EARN24 SG with Admin Dashboard

// --- 1. Import Dependencies ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');

// --- 2. Initialize Express App ---
const app = express();
const PORT = process.env.PORT || 3001;

// --- 3. Security Middleware ---
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
}));

const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again after 15 minutes.'
});

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());

// --- 4. Database Connection ---
const dbURI = process.env.MONGODB_URI;
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Successfully connected to MongoDB database.'))
    .catch(err => console.error('❌ Database connection error:', err));

// --- 5. Database Schemas ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true, minlength: 6 },
    balance: { type: Number, default: 0, min: 0 },
    totalEarned: { type: Number, default: 0, min: 0 },
    isAdmin: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    registrationDate: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    completedTasks: [{ 
        opportunityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Opportunity' },
        completedAt: { type: Date, default: Date.now },
        reward: { type: Number, required: true }
    }]
});

const OpportunitySchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    reward: { type: Number, required: true, min: 0 },
    type: { type: String, enum: ['Survey', 'Video', 'App Test', 'Game', 'Cashback', 'Referral'], required: true },
    isActive: { type: Boolean, default: true },
    maxCompletions: { type: Number, default: null },
    currentCompletions: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: null }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['earning', 'withdrawal', 'bonus', 'refund'], required: true },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    createdAt: { type: Date, default: Date.now }
});

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 10 },
    method: { type: String, enum: ['PayPal', 'Bank Transfer', 'Gift Card'], required: true },
    accountDetails: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);
const Opportunity = mongoose.model('Opportunity', OpportunitySchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);

// --- 6. Middleware Functions ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access token required.' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

const authorizeAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Admin access required.' });
        }
        next();
    } catch (error) {
        res.status(500).json({ message: 'Authorization error.' });
    }
};

// --- 7. API Routes ---
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/register', [
    body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ 
                message: existingUser.email === email ? 
                    'An account with this email already exists.' : 
                    'This username is already taken.' 
            });
        }
        const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        const welcomeBonus = new Transaction({
            userId: newUser._id, type: 'bonus', amount: 5,
            description: 'Welcome bonus for new registration'
        });
        await welcomeBonus.save();
        newUser.balance = 5;
        newUser.totalEarned = 5;
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully! Welcome bonus of $5 credited.' });
    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/login', authLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Invalid email or password format.' });
        }
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !user.isActive) {
            return res.status(400).json({ message: 'Invalid credentials or account inactive.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        user.lastLogin = new Date();
        await user.save();
        const payload = { userId: user._id, username: user.username, isAdmin: user.isAdmin };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });
        res.json({ 
            token, 
            user: {
                id: user._id, username: user.username, email: user.email,
                balance: user.balance, isAdmin: user.isAdmin
            },
            message: 'Logged in successfully!' 
        });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching profile.' });
    }
});

app.get('/api/opportunities', async (req, res) => {
    try {
        const opportunities = await Opportunity.find({ isActive: true });
        res.json(opportunities);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching opportunities.' });
    }
});

app.post('/api/tasks/complete', authenticateToken, [
    body('opportunityId').isMongoId()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }
        const { opportunityId } = req.body;
        const opportunity = await Opportunity.findById(opportunityId);
        if (!opportunity || !opportunity.isActive) {
            return res.status(404).json({ message: 'Opportunity not found or inactive.' });
        }
        const user = await User.findById(req.user.userId);
        user.balance += opportunity.reward;
        user.totalEarned += opportunity.reward;
        user.completedTasks.push({ opportunityId: opportunity._id, reward: opportunity.reward });
        await user.save();
        const transaction = new Transaction({
            userId: user._id, type: 'earning', amount: opportunity.reward,
            description: `Completed: ${opportunity.title}`
        });
        await transaction.save();
        opportunity.currentCompletions += 1;
        await opportunity.save();
        res.json({ message: `Task completed! You earned $${opportunity.reward}`, newBalance: user.balance });
    } catch (error) {
        res.status(500).json({ message: 'Error completing task.' });
    }
});

app.post('/api/withdrawal/request', authenticateToken, [
    body('amount').isFloat({ min: 10 }),
    body('method').isIn(['PayPal', 'Bank Transfer', 'Gift Card']),
    body('accountDetails').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }
        const { amount, method, accountDetails } = req.body;
        const user = await User.findById(req.user.userId);
        if (user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance.' });
        }
        user.balance -= amount;
        await user.save();
        const withdrawal = new Withdrawal({ userId: user._id, amount, method, accountDetails });
        await withdrawal.save();
        const transaction = new Transaction({
            userId: user._id, type: 'withdrawal', amount: -amount,
            description: `Withdrawal request via ${method}`, status: 'pending'
        });
        await transaction.save();
        res.json({ message: 'Withdrawal request submitted successfully!', withdrawalId: withdrawal._id });
    } catch (error) {
        res.status(500).json({ message: 'Error processing withdrawal.' });
    }
});

app.get('/api/user/transactions', authenticateToken, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(50);
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching transactions.' });
    }
});

// ===== ADMIN ENDPOINTS =====
app.get('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ registrationDate: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users.' });
    }
});

app.get('/api/admin/stats', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalOpportunities = await Opportunity.countDocuments();
        const activeOpportunities = await Opportunity.countDocuments({ isActive: true });
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        const totalEarnings = await Transaction.aggregate([
            { $match: { type: 'earning' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const totalWithdrawals = await Transaction.aggregate([
            { $match: { type: 'withdrawal', status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        res.json({
            totalUsers, activeUsers, totalOpportunities, activeOpportunities, pendingWithdrawals,
            totalEarnings: totalEarnings[0]?.total || 0,
            totalWithdrawals: Math.abs(totalWithdrawals[0]?.total || 0)
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching stats.' });
    }
});

app.post('/api/admin/opportunities', authenticateToken, authorizeAdmin, [
    body('title').trim().notEmpty(),
    body('description').trim().notEmpty(),
    body('reward').isFloat({ min: 0 }),
    body('type').isIn(['Survey', 'Video', 'App Test', 'Game', 'Cashback', 'Referral'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }
        const opportunity = new Opportunity(req.body);
        await opportunity.save();
        res.status(201).json({ message: 'Opportunity created successfully!', opportunity });
    } catch (error) {
        res.status(500).json({ message: 'Error creating opportunity.' });
    }
});

app.put('/api/admin/opportunities/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const opportunity = await Opportunity.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!opportunity) return res.status(404).json({ message: 'Opportunity not found.' });
        res.json({ message: 'Opportunity updated successfully!', opportunity });
    } catch (error) {
        res.status(500).json({ message: 'Error updating opportunity.' });
    }
});

app.delete('/api/admin/opportunities/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const opportunity = await Opportunity.findByIdAndDelete(req.params.id);
        if (!opportunity) return res.status(404).json({ message: 'Opportunity not found.' });
        res.json({ message: 'Opportunity deleted successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting opportunity.' });
    }
});

app.get('/api/admin/withdrawals', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find().populate('userId', 'username email').sort({ requestedAt: -1 });
        res.json(withdrawals);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching withdrawals.' });
    }
});

app.put('/api/admin/withdrawals/:id', authenticateToken, authorizeAdmin, [
    body('status').isIn(['approved', 'rejected', 'completed'])
], async (req, res) => {
    try {
        const { status } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal) return res.status(404).json({ message: 'Withdrawal not found.' });
        if (status === 'rejected') {
            const user = await User.findById(withdrawal.userId);
            user.balance += withdrawal.amount;
            await user.save();
            const transaction = new Transaction({
                userId: user._id, type: 'refund', amount: withdrawal.amount,
                description: 'Withdrawal request rejected - amount refunded'
            });
            await transaction.save();
        }
        if (status === 'completed') {
            await Transaction.updateOne(
                { userId: withdrawal.userId, type: 'withdrawal', amount: -withdrawal.amount },
                { status: 'completed' }
            );
        }
        withdrawal.status = status;
        withdrawal.processedAt = new Date();
        await withdrawal.save();
        res.json({ message: `Withdrawal ${status} successfully!`, withdrawal });
    } catch (error) {
        res.status(500).json({ message: 'Error processing withdrawal.' });
    }
});

app.put('/api/admin/users/:id/toggle', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });
        user.isActive = !user.isActive;
        await user.save();
        res.json({ message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully!`, user });
    } catch (error) {
        res.status(500).json({ message: 'Error toggling user status.' });
    }
});

// --- 8. Initialize Admin Account ---
async function initializeAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@earn24sg.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';
        const existingAdmin = await User.findOne({ email: adminEmail });
        if (!existingAdmin) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(adminPassword, salt);
            const admin = new User({
                username: 'admin', email: adminEmail, password: hashedPassword,
                isAdmin: true, balance: 0
            });
            await admin.save();
            console.log('✅ Admin account created successfully!');
            console.log(`📧 Email: ${adminEmail}`);
            console.log(`🔑 Password: ${adminPassword}`);
        }
    } catch (error) {
        console.error('Error initializing admin:', error);
    }
}

// --- 9. Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Backend server for EARN24 SG is running on http://localhost:${PORT}`);
    console.log(`🔒 Security features enabled: Helmet, Rate Limiting, Sanitization`);
    initializeAdmin();
});

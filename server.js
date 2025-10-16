// server.js - Backend for EARN24 SG (Version 5 - With Admin Panel & Full Features)

// --- 1. Import Dependencies ---
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const { nanoid } = require('nanoid');

// --- 2. Initialize Express App ---
const app = express();
const PORT = process.env.PORT || 3001;

// --- 3. Middleware ---
app.use(cors());
app.use(express.json());

// --- 4. Security First: Environment Variables ---
const dbURI = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET;
// --- Dev-only Admin Creation ---
const devAdminEmail = process.env.DEV_ADMIN_EMAIL;
const devAdminPassword = process.env.DEV_ADMIN_PASSWORD;

// --- 5. Database Connection & Initial Admin Setup ---
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Successfully connected to MongoDB database.');
        // Create a default admin user on first start if specified in environment
        if (devAdminEmail && devAdminPassword) {
            createDevAdmin();
        }
    })
    .catch(err => console.error('Database connection error:', err));


// --- 6. Database Schemas (Upgraded with Roles) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    balanceUSDT: { type: Number, default: 0 },
    points: { type: Number, default: 0 },
    referralCode: { type: String, unique: true, default: () => nanoid(8) },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    registrationDate: { type: Date, default: Date.now }
});

const OpportunitySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    reward: { type: Number, required: true },
    type: { type: String, default: 'Survey' }
});

const User = mongoose.model('User', UserSchema);
const Opportunity = mongoose.model('Opportunity', OpportunitySchema);


// --- Helper for creating dev admin ---
const createDevAdmin = async () => {
    try {
        const existingAdmin = await User.findOne({ email: devAdminEmail });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(devAdminPassword, 10);
            const adminUser = new User({
                username: 'Admin',
                email: devAdminEmail,
                password: hashedPassword,
                role: 'admin'
            });
            await adminUser.save();
            console.log('Development admin user created successfully.');
        } else {
            console.log('Development admin user already exists.');
        }
    } catch (error) {
        console.error('Error creating development admin user:', error);
    }
};


// --- 7. Security Middleware (User & Admin) ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authorization denied. No token provided.' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid.' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ message: 'Access denied. Admin privileges required.' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error during admin verification.' });
    }
};


// --- 8. API Routes ---

// == PUBLIC ROUTES ==
app.get('/api/opportunities', async (req, res) => {
    try {
        const opportunities = await Opportunity.find().sort({ _id: -1 });
        res.json({ opportunities });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching opportunities.' });
    }
});

// == AUTHENTICATION ROUTES ==
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, referrerCode } = req.body;
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) return res.status(400).json({ message: 'Email or username is already in use.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        let referredBy = null;
        if (referrerCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                referredBy = referrer._id;
                referrer.points += 500;
                await referrer.save();
            }
        }
        const newUser = new User({ username, email, password: hashedPassword, referredBy });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '24h' });
        res.json({ token, message: 'Logged in successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Not an admin.' });
        }
        const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '8h' });
        res.json({ token, message: 'Admin authenticated successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during admin login.' });
    }
});


// == USER ROUTES (Protected) ==
app.get('/api/user/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        let currency = 'SGD'; let rate = 1.35;
        try {
            const geoResponse = await axios.get(`http://ip-api.com/json/${ip.split(',')[0]}?fields=currency`);
            const userCurrency = geoResponse.data.currency || 'SGD';
            if (userCurrency !== 'USDT' && userCurrency !== 'USD') {
                 const rateResponse = await axios.get(`https://api.exchangerate-api.com/v4/latest/USD`);
                 if(rateResponse.data.rates[userCurrency]) {
                     currency = userCurrency;
                     rate = rateResponse.data.rates[userCurrency];
                 }
            }
        } catch (apiError) { console.log("Could not fetch currency, using default."); }
        const balanceLocal = { currency, amount: (user.balanceUSDT * rate).toFixed(2) };
        res.json({ user, balanceLocal });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching user data.' });
    }
});

app.post('/api/rewards/redeem', authMiddleware, async (req, res) => {
    try {
        const { pointsToRedeem } = req.body;
        if (!pointsToRedeem || pointsToRedeem < 1000) return res.status(400).json({ message: 'Minimum 1000 points required.' });
        const user = await User.findById(req.user.userId);
        if (user.points < pointsToRedeem) return res.status(400).json({ message: 'Insufficient points.' });
        const usdtToAdd = pointsToRedeem / 1000;
        user.points -= pointsToRedeem;
        user.balanceUSDT += usdtToAdd;
        await user.save();
        res.json({ message: `${pointsToRedeem} points redeemed for ${usdtToAdd.toFixed(2)} USDT!` });
    } catch (error) {
        res.status(500).json({ message: 'Server error during redemption.' });
    }
});


// == ADMIN ROUTES (Protected) ==
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ role: 'user' });
        const totalOpportunities = await Opportunity.countDocuments();
        res.json({ totalUsers, totalOpportunities });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching stats.' });
    }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).select('-password').sort({ registrationDate: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching users.' });
    }
});

app.post('/api/admin/opportunities', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { title, description, reward } = req.body;
        const newOpportunity = new Opportunity({ title, description, reward });
        await newOpportunity.save();
        res.status(201).json({ message: 'Opportunity added successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error adding opportunity.' });
    }
});

app.delete('/api/admin/opportunities/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await Opportunity.findByIdAndDelete(req.params.id);
        if (!result) return res.status(404).json({ message: 'Opportunity not found.' });
        res.json({ message: 'Opportunity deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting opportunity.' });
    }
});


// --- 9. Start the Server ---
app.listen(PORT, () => {
    console.log(`Backend server for EARN24 SG is running on port: ${PORT}`);
});


// --- MOVE ALL IMPORTS AND APP INIT TO THE TOP ---
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require("express-session");
const MongoStore = require('connect-mongo');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware setup
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs for auth endpoints
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // limit each IP to 10 uploads per hour
    message: 'Too many file uploads, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting
app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/account/profile-pic', uploadLimiter);

// Debug middleware to log all requests
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp());

// Secure CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'https://sap-technologies.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Set up middleware first
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// Input validation middleware
const validateInput = (req, res, next) => {
    const sanitizeString = (str) => {
        if (typeof str !== 'string') return '';
        return validator.escape(validator.trim(str));
    };

    const sanitizeEmail = (email) => {
        if (!email || typeof email !== 'string') return '';
        return validator.normalizeEmail(validator.trim(email));
    };

    // Sanitize body parameters
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                if (key === 'email') {
                    req.body[key] = sanitizeEmail(req.body[key]);
                } else {
                    req.body[key] = sanitizeString(req.body[key]);
                }
            }
        });
    }

    // Sanitize query parameters
    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === 'string') {
                req.query[key] = sanitizeString(req.query[key]);
            }
        });
    }

    next();
};

app.use(validateInput);

// Newsletter Subscription Model
const newsletterSchema = new mongoose.Schema({
    email: { 
        type: String, 
        required: true, 
        unique: true,
        validate: {
            validator: validator.isEmail,
            message: 'Please provide a valid email address'
        }
    },
    subscribedAt: { type: Date, default: Date.now }
});
const NewsletterSubscriber = mongoose.model('NewsletterSubscriber', newsletterSchema);

// Newsletter subscription endpoint
app.post('/api/newsletter/subscribe', async (req, res) => {
    const { email } = req.body;
    
    // Additional validation
    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email address.' });
    }
    
    // Check email length
    if (email.length > 254) {
        return res.status(400).json({ message: 'Email address too long.' });
    }
    
    try {
        const existing = await NewsletterSubscriber.findOne({ email });
        if (existing) {
            return res.status(200).json({ message: 'You are already subscribed.' });
        }
        await NewsletterSubscriber.create({ email });
        res.status(201).json({ message: 'Thank you for subscribing!' });
    } catch (err) {
        console.error('Newsletter subscription error:', err);
        res.status(500).json({ message: 'Subscription failed. Please try again later.' });
    }
});

// Contact Form Model
const contactSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true,
        maxlength: 100,
        validate: {
            validator: function(v) {
                return /^[a-zA-Z\s]+$/.test(v) && v.length >= 2;
            },
            message: 'Name must be at least 2 characters and contain only letters and spaces'
        }
    },
    email: { 
        type: String, 
        required: true,
        validate: {
            validator: validator.isEmail,
            message: 'Please provide a valid email address'
        }
    },
    message: { 
        type: String, 
        required: true,
        maxlength: 1000,
        validate: {
            validator: function(v) {
                return v.length >= 10 && v.length <= 1000;
            },
            message: 'Message must be between 10 and 1000 characters'
        }
    },
    submittedAt: { type: Date, default: Date.now },
    status: { type: String, enum: ['new', 'read', 'replied'], default: 'new' },
    ipAddress: { type: String },
    userAgent: { type: String }
});
const Contact = mongoose.model('Contact', contactSchema);

// Allow CORS for API endpoints (adjust origin as needed)
app.use('/api', cors());

app.use(session({
    secret: process.env.SESSION_SECRET || 'sap_technologies_secret_key_change_in_production',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/sap_technologies',
        ttl: 24 * 60 * 60, // 1 day
        autoRemove: 'native'
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 1 day
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    },
    name: 'sessionId' // Change default session name
}));

// MongoDB connection with fallback options
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/sap_technologies';
console.log('Attempting to connect to MongoDB:', mongoUri);

mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log('MongoDB database connected successfully'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    console.log('Please ensure MongoDB is running or set MONGODB_URI environment variable');
    console.log('For local development, you can install MongoDB or use MongoDB Atlas');
});

// Update user schema for profile picture, registration date, and activity log
const userSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true,
        maxlength: 50,
        validate: {
            validator: function(v) {
                return /^[a-zA-Z\s]+$/.test(v) && v.length >= 2;
            },
            message: 'Name must be at least 2 characters and contain only letters and spaces'
        }
    },
    email: { 
        type: String, 
        required: true, 
        unique: true,
        validate: {
            validator: validator.isEmail,
            message: 'Please provide a valid email address'
        }
    },
    password: { 
        type: String, 
        required: true,
        minlength: 8
    },
    profilePic: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    activity: [{ type: String, default: [] }],
    lastLogin: { type: Date },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date }
});
const User = mongoose.model('User', userSchema);

// Secure file upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../public/profile-pics'));
    },
    filename: (req, file, cb) => {
        // Generate secure filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'profile-' + uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    // Check file type
    if (!file.mimetype.startsWith('image/')) {
        return cb(new Error('Only image files are allowed'), false);
    }
    
    // Check file extension
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
        return cb(new Error('Invalid file extension'), false);
    }
    
    // Check file size (2MB limit)
    if (file.size > 2 * 1024 * 1024) {
        return cb(new Error('File size too large. Maximum 2MB allowed.'), false);
    }
    
    cb(null, true);
};

const upload = multer({
    storage: storage,
    limits: { 
        fileSize: 2 * 1024 * 1024, // 2MB
        files: 1
    },
    fileFilter: fileFilter
});

// Auth middleware with additional security
function requireLogin(req, res, next) {
    console.log('requireLogin check:', {
        hasSession: !!req.session,
        hasUserId: !!(req.session && req.session.userId),
        userId: req.session ? req.session.userId : 'no session',
        sessionId: req.session ? req.session.id : 'no session id'
    });
    
    if (req.session && req.session.userId) {
        // Check if session is not expired
        if (req.session.cookie.expires && new Date() > req.session.cookie.expires) {
            console.log('Session expired, destroying session');
            req.session.destroy();
            return res.status(401).json({ message: 'Session expired. Please login again.' });
        }
        return next();
    }
    console.log('No valid session found, returning 401');
    res.status(401).json({ message: 'Unauthorized' });
}

// Helper function to safely delete profile picture
function deleteProfilePicture(picPath) {
    if (!picPath || picPath === '') return;
    
    try {
        const fullPath = path.join(__dirname, '../public', picPath);
        if (require('fs').existsSync(fullPath)) {
            require('fs').unlinkSync(fullPath);
            console.log('Profile picture deleted:', fullPath);
            return true;
        }
    } catch (err) {
        console.log('Error deleting profile picture:', err.message);
    }
    return false;
}

// Contact form endpoint with enhanced security
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;
    
    // Enhanced validation
    if (!name || !email || !message) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Please enter a valid email address.' });
    }
    
    if (name.length < 2 || name.length > 100) {
        return res.status(400).json({ message: 'Name must be between 2 and 100 characters.' });
    }
    
    if (message.length < 10 || message.length > 1000) {
        return res.status(400).json({ message: 'Message must be between 10 and 1000 characters.' });
    }
    
    try {
        // Store contact form submission in database with additional security info
        await Contact.create({ 
            name, 
            email, 
            message,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });
        res.status(201).json({ success: true, message: 'Thank you for your message! We will get back to you soon.' });
    } catch (err) {
        console.error('Contact form error:', err);
        res.status(500).json({ message: 'Failed to submit message. Please try again later.' });
    }
});

// Enhanced signup endpoint with security
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        console.log('Signup attempt:', { name, email, password: password ? '***' : 'missing' });
        
        // Enhanced validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields required.' });
        }
        
        // Validate name format
        if (!/^[a-zA-Z\s]+$/.test(name)) {
            return res.status(400).json({ message: 'Name can only contain letters and spaces.' });
        }
        
        if (name.length < 2 || name.length > 50) {
            return res.status(400).json({ message: 'Name must be between 2 and 50 characters.' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: 'Please provide a valid email address.' });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
        }
        
        // Check for strong password
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.' 
            });
        }
        
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ message: 'Email already registered.' });
        
        const hashed = await bcrypt.hash(password, 12); // Increased salt rounds
        const user = new User({ name, email, password: hashed });
        await user.save();
        
        console.log('User created successfully:', { email, name });
        res.status(201).json({ message: 'Signup successful.' });
    } catch (err) {
        console.error('Signup error:', err);
        
        // Handle specific validation errors
        if (err.name === 'ValidationError') {
            const messages = Object.values(err.errors).map(e => e.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        
        // Handle duplicate key error
        if (err.code === 11000) {
            return res.status(400).json({ message: 'Email already registered.' });
        }
        
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// Enhanced login endpoint with security
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'All fields required.' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: 'Please provide a valid email address.' });
        }
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        
        // Check if account is locked
        if (user.lockUntil && user.lockUntil > Date.now()) {
            return res.status(423).json({ 
                message: `Account is locked. Try again after ${new Date(user.lockUntil).toLocaleString()}` 
            });
        }
        
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            // Increment login attempts
            user.loginAttempts += 1;
            
            // Lock account after 5 failed attempts for 15 minutes
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
            }
            
            await user.save();
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        
        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lockUntil = null;
        user.lastLogin = new Date();
        await user.save();
        
        req.session.userId = user._id;
        req.session.userName = user.name;
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ message: 'Session error.' });
            }
            res.status(200).json({ message: 'Login successful.', name: user.name });
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout error.' });
        }
        res.clearCookie('sessionId');
        res.status(200).json({ message: 'Logged out' });
    });
});

// Update email with enhanced security
app.put('/api/account/email', requireLogin, async (req, res) => {
    const { email } = req.body;
    
    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ message: 'Please provide a valid email address.' });
    }
    
    try {
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ message: 'Email already in use.' });
        
        const user = await User.findByIdAndUpdate(req.session.userId, { email }, { new: true }).select('-password');
        user.activity.push('Changed email');
        await user.save();
        res.json({ user, message: 'Email updated.' });
    } catch (err) {
        console.error('Email update error:', err);
        res.status(500).json({ message: 'Failed to update email.' });
    }
});

// Update password with enhanced security
app.put('/api/account/password', requireLogin, async (req, res) => {
    const { password } = req.body;
    
    if (!password || password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }
    
    // Check for strong password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
            message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.' 
        });
    }
    
    try {
        const hashed = await bcrypt.hash(password, 12);
        const user = await User.findByIdAndUpdate(req.session.userId, { password: hashed }, { new: true }).select('-password');
        user.activity.push('Changed password');
        await user.save();
        res.json({ message: 'Password updated.' });
    } catch (err) {
        console.error('Password update error:', err);
        res.status(500).json({ message: 'Failed to update password.' });
    }
});

// Upload profile picture with enhanced security
app.post('/api/account/profile-pic', requireLogin, upload.single('profilePic'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded.' });
        }
        
        const user = await User.findById(req.session.userId);
        
        // Delete old profile picture if it exists
        deleteProfilePicture(user.profilePic);
        
        // Update with new profile picture
        user.profilePic = '/profile-pics/' + req.file.filename;
        user.activity.push('Updated profile picture');
        await user.save();
        
        res.json({ profilePic: user.profilePic });
    } catch (err) {
        console.error('Profile picture upload error:', err);
        res.status(500).json({ message: 'Failed to upload profile picture.' });
    }
});

// Account endpoint (protected)
app.get('/api/account', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        res.json({ user });
    } catch (err) {
        console.error('Account fetch error:', err);
        res.status(500).json({ message: 'Failed to fetch account information.' });
    }
});

// Update account (name) with enhanced security
app.put('/api/account', requireLogin, async (req, res) => {
    const { name } = req.body;
    
    if (!name || name.length < 2 || name.length > 50) {
        return res.status(400).json({ message: 'Name must be between 2 and 50 characters.' });
    }
    
    // Validate name format
    if (!/^[a-zA-Z\s]+$/.test(name)) {
        return res.status(400).json({ message: 'Name can only contain letters and spaces.' });
    }
    
    try {
        const user = await User.findByIdAndUpdate(req.session.userId, { name }, { new: true }).select('-password');
        res.json({ user, message: 'Name updated successfully.' });
    } catch (err) {
        console.error('Name update error:', err);
        res.status(500).json({ message: 'Failed to update name.' });
    }
});

// Delete account with enhanced security
app.delete('/api/account', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        // Delete profile picture if it exists
        deleteProfilePicture(user.profilePic);
        
        // Delete user from database
        await User.findByIdAndDelete(req.session.userId);
        
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ message: 'Account deletion error.' });
            }
            res.clearCookie('sessionId');
            res.status(200).json({ message: 'Account deleted.' });
        });
    } catch (err) {
        console.error('Account deletion error:', err);
        res.status(500).json({ message: 'Failed to delete account.' });
    }
});

// Admin endpoints for managing contact submissions and newsletter subscribers
// Get all contact submissions (protected)
app.get('/api/admin/contacts', requireLogin, async (req, res) => {
    try {
        const contacts = await Contact.find().sort({ submittedAt: -1 });
        res.json({ contacts });
    } catch (err) {
        console.error('Contacts fetch error:', err);
        res.status(500).json({ message: 'Failed to fetch contacts.' });
    }
});

// Update contact status (protected)
app.put('/api/admin/contacts/:id', requireLogin, async (req, res) => {
    const { status } = req.body;
    if (!['new', 'read', 'replied'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status.' });
    }
    try {
        const contact = await Contact.findByIdAndUpdate(req.params.id, { status }, { new: true });
        res.json({ contact });
    } catch (err) {
        console.error('Contact status update error:', err);
        res.status(500).json({ message: 'Failed to update contact status.' });
    }
});

// Get all newsletter subscribers (protected)
app.get('/api/admin/newsletter', requireLogin, async (req, res) => {
    try {
        const subscribers = await NewsletterSubscriber.find().sort({ subscribedAt: -1 });
        res.json({ subscribers });
    } catch (err) {
        console.error('Newsletter subscribers fetch error:', err);
        res.status(500).json({ message: 'Failed to fetch subscribers.' });
    }
});

// Delete newsletter subscriber (protected)
app.delete('/api/admin/newsletter/:id', requireLogin, async (req, res) => {
    try {
        await NewsletterSubscriber.findByIdAndDelete(req.params.id);
        res.json({ message: 'Subscriber removed successfully.' });
    } catch (err) {
        console.error('Newsletter subscriber deletion error:', err);
        res.status(500).json({ message: 'Failed to remove subscriber.' });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', requireLogin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json({ users });
    } catch (err) {
        console.error('Users fetch error:', err);
        res.status(500).json({ message: 'Failed to fetch users.' });
    }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        
        // Delete profile picture if it exists
        deleteProfilePicture(user.profilePic);
        
        // Delete user from database
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully.' });
    } catch (err) {
        console.error('User deletion error:', err);
        res.status(500).json({ message: 'Failed to delete user.' });
    }
});

// Check if user is admin
app.get('/api/admin/check', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        // For now, we'll use a simple email-based admin check
        // You can modify this to use a role field in the user schema
        const isAdmin = user.email === 'admin@sap-technologies.com' || 
                       user.email === 'info@sap-technologies.com' ||
                       user.email === 'support@sap-technologies.com';
        res.json({ isAdmin, user });
    } catch (err) {
        console.error('Admin check error:', err);
        res.status(500).json({ message: 'Failed to check admin status.' });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        await mongoose.connection.db.admin().ping();
        res.json({ 
            status: 'healthy', 
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Health check failed:', err);
        res.status(500).json({ 
            status: 'unhealthy', 
            database: 'disconnected',
            error: err.message 
        });
    }
});

// Serve static files after API routes
app.use(express.static(path.join(__dirname, '../public')));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal server error.' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found.' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

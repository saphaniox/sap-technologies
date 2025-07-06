/**
 * Security Configuration for SAP Technologies
 * 
 * This file contains security settings and recommendations for the application.
 * Make sure to implement all these security measures in production.
 */

module.exports = {
    // Session Security
    session: {
        secret: process.env.SESSION_SECRET || 'sap_technologies_secret_key_change_in_production',
        name: 'sessionId', // Changed from default 'connect.sid'
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        },
        resave: false,
        saveUninitialized: false
    },

    // Rate Limiting
    rateLimit: {
        general: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100 // limit each IP to 100 requests per windowMs
        },
        auth: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5 // limit each IP to 5 auth requests per windowMs
        },
        upload: {
            windowMs: 60 * 60 * 1000, // 1 hour
            max: 10 // limit each IP to 10 uploads per hour
        }
    },

    // CORS Configuration
    cors: {
        origin: process.env.ALLOWED_ORIGINS ? 
            process.env.ALLOWED_ORIGINS.split(',') : 
            ['http://localhost:3000', 'https://sap-technologies.com'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization']
    },

    // File Upload Security
    fileUpload: {
        maxSize: 2 * 1024 * 1024, // 2MB
        allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        allowedExtensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
        uploadPath: 'public/profile-pics'
    },

    // Password Security
    password: {
        minLength: 8,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        saltRounds: 12
    },

    // Account Security
    account: {
        maxLoginAttempts: 5,
        lockoutDuration: 15 * 60 * 1000, // 15 minutes
        sessionTimeout: 24 * 60 * 60 * 1000 // 1 day
    },

    // Input Validation
    validation: {
        name: {
            minLength: 2,
            maxLength: 50,
            pattern: /^[a-zA-Z\s]+$/
        },
        email: {
            maxLength: 254
        },
        message: {
            minLength: 10,
            maxLength: 1000
        }
    },

    // Security Headers
    headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    },

    // Content Security Policy
    csp: {
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

    // MongoDB Security
    mongodb: {
        options: {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000
        }
    },

    // Admin Emails (for admin access)
    adminEmails: [
        'admin@sap-technologies.com',
        'info@sap-technologies.com',
        'support@sap-technologies.com'
    ],

    // Security Recommendations
    recommendations: [
        'Use HTTPS in production',
        'Regularly update dependencies',
        'Monitor logs for suspicious activity',
        'Implement proper backup strategies',
        'Use environment variables for sensitive data',
        'Regular security audits',
        'Implement API rate limiting',
        'Use strong password policies',
        'Enable two-factor authentication if possible',
        'Regular database backups',
        'Monitor failed login attempts',
        'Implement proper error handling',
        'Use secure session management',
        'Validate and sanitize all inputs',
        'Implement proper CORS policies',
        'Use security headers',
        'Regular penetration testing',
        'Keep server software updated',
        'Use firewall protection',
        'Implement proper logging'
    ]
}; 
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5001;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Parse multiple frontend origins if comma-separated
const allowedOrigins = FRONTEND_URL.split(',').map(url => url.trim());

// Helper to identify local developer origins dynamically
const isLocalhost = (origin) => {
  if (!origin) return false;
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.') ||
      hostname.endsWith('.local')
    );
  } catch (e) {
    return false;
  }
};

// Configure CORS securely (restrict to FRONTEND_URL in production, dynamically allow local network IPs in development)
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || isLocalhost(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// Rate limiter for authentication endpoints (prevent brute-force abuse)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Limit each IP to 15 requests per 15 minutes
  message: {
    success: false,
    message: 'Too many requests from this IP. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json());

// Logger middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

/**
 * POST /api/auth/login
 * Core login logic matching email and password credentials
 */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }

  try {
    const user = await db.getUserByEmail(email);
    if (!user) {
      // Security practice: Avoid specifying if email or password was wrong to prevent email enumeration
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    const isValid = await db.validatePassword(user, password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Success response
    return res.json({
      success: true,
      message: 'Login successful.',
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/forgot-password
 * Verifies email exists, generates a reset token, updates db, logs URL link
 */
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required.' });
  }

  try {
    const user = await db.getUserByEmail(email);
    
    // Always return a generic success message to prevent user enumeration
    const genericResponse = {
      success: true,
      message: 'If the email is registered in our system, you will receive a password reset link shortly.'
    };

    if (!user) {
      console.log(`[Forgot Password] Requested email '${email}' not found in database.`);
      return res.json(genericResponse);
    }

    // Generate secure random token
    const token = crypto.randomBytes(32).toString('hex');
    await db.setResetToken(email, token);

    // Create the recovery reset link matching our frontend URL
    const resetUrl = `${FRONTEND_URL}/?token=${token}`;

    console.log('\n=========================================');
    console.log(`[EMAIL DISPATCH MOCK] to: ${email}`);
    console.log('-----------------------------------------');
    console.log('Subject: Simple Gatekeeper - Password Reset Request');
    console.log(`Please click the link below to reset your password (valid for 1 hour):`);
    console.log(resetUrl);
    console.log('=========================================\n');

    return res.json(genericResponse);
  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

/**
 * GET /api/auth/verify-token
 * Verifies if a password reset token exists and is valid (proactive client-side validation)
 */
app.get('/api/auth/verify-token', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ success: false, message: 'Token query parameter is required.' });
  }

  try {
    const user = await db.getUserByResetToken(token);
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired password reset token.' });
    }

    return res.json({
      success: true,
      message: 'Token is valid.',
      email: user.email
    });
  } catch (error) {
    console.error('Verify token error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/reset-password
 * Resets password using valid token
 */
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Token and new password are required.' });
  }

  // Basic validation
  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: 'New password must be at least 8 characters long.' });
  }

  try {
    const user = await db.getUserByResetToken(token);
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired password reset token.' });
    }

    await db.updatePassword(user, newPassword);
    console.log(`[Reset Password] Successfully updated password for user: ${user.email}`);

    return res.json({
      success: true,
      message: 'Your password has been successfully updated. You can now login with your new password.'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// Run server bound to all interfaces so it is reachable over LAN (not just localhost)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=========================================`);
  console.log(`Simple Gatekeeper API running on port ${PORT}`);
  console.log(`Listening on: http://0.0.0.0:${PORT}`);
  console.log(`Allowed CORS Origin: ${FRONTEND_URL}`);
  console.log(`Mock accounts available:`);
  console.log(`  - admin@lestaz.tech / LestazTech2026!`);
  console.log(`  - user@lestaz.tech  / Password123!`);
  console.log(`=========================================`);
});

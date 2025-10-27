const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sgMail = require('@sendgrid/mail');
const admin = require('firebase-admin');
require('dotenv').config();

// --- App Initialization ---
const app = express();
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// --- Firebase Admin Initialization ---
// !! IMPORTANT !!
// You must download your "serviceAccountKey.json" from Firebase
// and place it in this directory for push notifications to work.
try {
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin SDK initialized.');
} catch (error) {
  console.warn('⚠️ Firebase Admin SDK failed to initialize. Push notifications will not work.');
  console.warn('Error:', error.message);
}


// --- Middleware ---
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// --- PostgreSQL Connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('connect', () => console.log('✅ PostgreSQL connected successfully'));
pool.on('error', (err) => console.error('❌ PostgreSQL connection error:', err));


// --- Helper Functions ---
/**
 * Generates a random 6-digit numeric code.
 * @returns {string} A 6-digit code.
 */
const generateCode = (length = 6) => {
  return crypto.randomInt(10**(length-1), 10**length - 1).toString();
};

/**
 * Sends an email using SendGrid.
 * @param {string} to - Recipient email.
 * @param {string} subject - Email subject.
 * @param {string} templatePath - Path to the HTML template.
 * @param {object} replacements - Key-value pairs to replace in the template (e.g., {user_name: "Test"}).
 */
const sendEmail = async (to, subject, templatePath, replacements = {}) => {
  try {
    const template = await fs.promises.readFile(path.join(__dirname, templatePath), 'utf-8');
    
    let html = template;
    for (const key in replacements) {
      html = html.replace(new RegExp(`{${key}}`, 'g'), replacements[key]);
    }

    const msg = {
      to,
      from: process.env.SENDGRID_VERIFIED_SENDER,
      subject: `QuickTop - ${subject}`,
      html: html,
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}: ${subject}`);
  } catch (error) {
    console.error(`❌ Failed to send email to ${to}:`, error.response ? error.response.body : error);
  }
};


// --- Authentication Middleware ---
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const userResult = await pool.query(
      'SELECT id, name, email, phone, country, is_verified, created_at FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    // Check if user is verified (optional, remove if not needed for all routes)
    if (!userResult.rows[0].is_verified) {
      // return res.status(403).json({ success: false, message: 'Please verify your email to access this route.' });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

const adminAuth = (req, res, next) => {
    try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'Admin access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.admin) {
        return res.status(403).json({ success: false, message: 'Forbidden: Admin access required' });
    }
    
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired admin token' });
  }
};


// --- Public Routes ---
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 QuickTop Backend API is running!',
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT NOW()');
    res.json({ success: true, message: '✅ API is healthy', database: 'connected' });
  } catch (error) {
    res.status(500).json({ success: false, message: '❌ API is unhealthy', database: 'disconnected' });
  }
});


// --- Auth Endpoints ---

// 1A. SIGNUP (Modified)
app.post('/api/auth/signup', async (req, res) => {
  console.log('📝 Signup request received:', req.body.email);
  try {
    const { name, email, phone, password, country, pin, referralCode } = req.body;

    // Validation
    if (!name || !email || !phone || !password || !country || !pin) {
      return res.status(400).json({ success: false, message: 'All fields are required: name, email, phone, password, country, pin' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
    }
    if (!/^\d{4}$/.test(pin)) {
        return res.status(400).json({ success: false, message: 'PIN must be exactly 4 digits' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1 OR phone = $2', [email, phone]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'User with this email or phone already exists' });
    }

    // Referral Logic
    let discount = 0.00;
    let referredByCodeId = null;
    if (referralCode) {
        const codeResult = await pool.query(
            'SELECT * FROM referral_codes WHERE code = $1 AND is_used = false AND (expiry_date IS NULL OR expiry_date > NOW())',
            [referralCode]
        );
        if (codeResult.rows.length > 0) {
            const codeData = codeResult.rows[0];
            discount = codeData.discount_percentage;
            referredByCodeId = codeData.id;
            if (codeData.is_single_use) {
                await pool.query('UPDATE referral_codes SET is_used = true WHERE id = $1', [codeData.id]);
            }
            // TODO: Credit the referrer (owner_user_id) if implementing that bonus
        }
    }

    // Hash passwords & codes
    const hashedPassword = await bcrypt.hash(password, 12);
    const hashedPin = await bcrypt.hash(pin, 12);
    const verificationCode = generateCode(6);
    const hashedVerificationCode = await bcrypt.hash(verificationCode, 12);
    const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Create user
    const userResult = await pool.query(
      `INSERT INTO users (name, email, phone, password, country, pin, is_verified, verification_code, verification_expires, signup_discount, referred_by_code_id) 
       VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9, $10) 
       RETURNING id, name, email, phone`,
      [name, email, phone, hashedPassword, country, hashedPin, hashedVerificationCode, verificationExpires, discount, referredByCodeId]
    );
    const user = userResult.rows[0];

    // Create wallet (default 0 balance)
    await pool.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0.00)', [user.id]);

    // Send verification email
    await sendEmail(
        user.email,
        'Verify Your Account',
        'emailver.html',
        { user_name: user.name, VERIFICATION_LINK: `Your code is ${verificationCode}` } // Note: Template expects a link, we send a code.
    );

    console.log(`✅ Verification code for ${user.email}: ${verificationCode}`);
    
    res.status(201).json({
      success: true,
      message: 'Verification email sent. Please check your inbox for the 6-digit code.'
    });

  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// 1B. VERIFY EMAIL (New)
app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) {
            return res.status(400).json({ success: false, message: 'Email and code are required' });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ success: false, message: 'User not found' });
        }

        const user = userResult.rows[0];
        if (user.is_verified) {
            return res.status(400).json({ success: false, message: 'Account already verified' });
        }

        if (user.verification_expires < new Date()) {
            return res.status(400).json({ success: false, message: 'Verification code has expired' });
        }

        const isCodeValid = await bcrypt.compare(code, user.verification_code);
        if (!isCodeValid) {
            return res.status(400).json({ success: false, message: 'Invalid verification code' });
        }

        // Verification successful
        await pool.query(
            'UPDATE users SET is_verified = true, verification_code = NULL, verification_expires = NULL WHERE id = $1',
            [user.id]
        );

        // Generate token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

        // Send welcome email
        await sendEmail(user.email, 'Welcome to QuickTop!', 'emailwel.html', { user_name: user.name });

        res.json({
            success: true,
            message: 'Email verified successfully!',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });

    } catch (error) {
        console.error('❌ Verify email error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 1C. RESEND CODE (New)
app.post('/api/auth/resend-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required' });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ success: false, message: 'User not found' });
        }
        
        const user = userResult.rows[0];
        if (user.is_verified) {
            return res.status(400).json({ success: false, message: 'Account already verified' });
        }

        // Generate new code
        const verificationCode = generateCode(6);
        const hashedVerificationCode = await bcrypt.hash(verificationCode, 12);
        const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        await pool.query(
            'UPDATE users SET verification_code = $1, verification_expires = $2 WHERE id = $3',
            [hashedVerificationCode, verificationExpires, user.id]
        );

        // Resend verification email
        await sendEmail(
            user.email,
            'New Verification Code',
            'emailver.html',
            { user_name: user.name, VERIFICATION_LINK: `Your new code is ${verificationCode}` }
        );

        console.log(`✅ Resent code for ${user.email}: ${verificationCode}`);
        res.json({ success: true, message: 'A new verification code has been sent.' });

    } catch (error) {
        console.error('❌ Resend code error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// LOGIN (Unchanged, but user must be verified)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Check if verified
    if (!user.is_verified) {
        return res.status(403).json({
            success: false,
            message: 'Account not verified. Please check your email for the verification code.'
        });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// --- Profile & Wallet Endpoints (Authenticated) ---

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// 2A. REQUEST PIN RESET (New)
app.post('/api/auth/request-pin-reset', authenticateToken, async (req, res) => {
    try {
        const user = req.user;
        
        const code = generateCode(6);
        const hashedCode = await bcrypt.hash(code, 12);
        const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await pool.query(
            'UPDATE users SET pin_reset_code = $1, pin_reset_expires = $2 WHERE id = $3',
            [hashedCode, expires, user.id]
        );

        await sendEmail(
            user.email,
            'Reset Your Transaction PIN',
            'forgotpin.html',
            { user_name: user.name, RESET_PIN_LINK: `Your 6-digit PIN reset code is ${code}` }
        );

        console.log(`✅ PIN reset code for ${user.email}: ${code}`);
        res.json({ success: true, message: 'A PIN reset code has been sent to your verified email.' });

    } catch (error) {
        console.error('❌ Request PIN reset error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 2B. VERIFY PIN RESET (New)
app.post('/api/auth/verify-pin-reset', authenticateToken, async (req, res) => {
    try {
        const { code, newPin } = req.body;
        const user = req.user;

        if (!code || !newPin) {
            return res.status(400).json({ success: false, message: 'Code and new PIN are required' });
        }
        if (!/^\d{4}$/.test(newPin)) {
            return res.status(400).json({ success: false, message: 'New PIN must be exactly 4 digits' });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [user.id]);
        const dbUser = userResult.rows[0];

        if (dbUser.pin_reset_expires < new Date()) {
            return res.status(400).json({ success: false, message: 'PIN reset code has expired' });
        }

        const isCodeValid = await bcrypt.compare(code, dbUser.pin_reset_code);
        if (!isCodeValid) {
            return res.status(400).json({ success: false, message: 'Invalid reset code' });
        }

        // Reset successful
        const hashedPin = await bcrypt.hash(newPin, 12);
        await pool.query(
            'UPDATE users SET pin = $1, pin_reset_code = NULL, pin_reset_expires = NULL WHERE id = $2',
            [hashedPin, user.id]
        );

        res.json({ success: true, message: 'Your transaction PIN has been successfully updated.' });

    } catch (error) {
        console.error('❌ Verify PIN reset error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 3B. GET USER'S OWN REFERRAL CODE (New)
app.get('/api/profile/referral-code', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Find existing multi-use code
        let codeResult = await pool.query(
            'SELECT code FROM referral_codes WHERE owner_user_id = $1 AND is_single_use = false',
            [userId]
        );

        if (codeResult.rows.length > 0) {
            return res.json({ success: true, code: codeResult.rows[0].code });
        }

        // Not found, generate a new one
        // Simple code: USERNAME (first 4) + 4 random digits
        const newCode = (req.user.name.substring(0, 4) + generateCode(4)).toUpperCase();
        
        const newCodeResult = await pool.query(
            `INSERT INTO referral_codes (code, discount_percentage, is_single_use, owner_user_id)
             VALUES ($1, 5.00, false, $2)
             RETURNING code`,
            [newCode, userId]
        );

        res.status(201).json({ success: true, code: newCodeResult.rows[0].code });

    } catch (error) {
        console.error('❌ Get referral code error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 4A. DELETE ACCOUNT (New)
app.delete('/api/profile/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        const userId = req.user.id;

        if (!password) {
            return res.status(400).json({ success: false, message: 'Password is required to delete account' });
        }

        const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
        const dbUser = userResult.rows[0];

        const isPasswordValid = await bcrypt.compare(password, dbUser.password);
        if (!isPasswordValid) {
            return res.status(400).json({ success: false, message: 'Invalid password' });
        }

        // Password is valid, proceed with deletion
        // ON DELETE CASCADE in init-db.js should handle wallets, transactions
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);

        res.json({ success: true, message: 'Account deleted successfully.' });

    } catch (error) {
        console.error('❌ Delete account error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});


app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT balance FROM wallets WHERE user_id = $1', [req.user.id]);
    res.json({
      success: true,
      balance: parseFloat(result.rows[0]?.balance || 0)
    });
  } catch (error) {
    console.error('Get balance error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Note: This is a MOCK funding endpoint for testing.
app.post('/api/wallet/fund', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Valid amount is required' });
    }
    const result = await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 RETURNING balance',
      [amount, req.user.id]
    );
    res.json({ success: true, message: 'Wallet funded successfully', newBalance: parseFloat(result.rows[0].balance) });
  } catch (error) {
    console.error('Fund wallet error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, type, service_type, amount, details, created_at 
       FROM transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 20`,
      [req.user.id]
    );
    res.json({ success: true, transactions: result.rows });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// --- Service Endpoints (PIN Required) ---

// AIRTIME PURCHASE (Modified for PIN)
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  try {
    const { network, phone, amount, pin } = req.body;
    const userId = req.user.id;

    if (!network || !phone || !amount || !pin) {
      return res.status(400).json({ success: false, message: 'Network, phone, amount, and PIN are required' });
    }

    // Verify PIN
    const userResult = await pool.query('SELECT pin, signup_discount FROM users WHERE id = $1', [userId]);
    const isPinValid = await bcrypt.compare(pin, userResult.rows[0].pin);
    if (!isPinValid) {
        return res.status(401).json({ success: false, message: 'Invalid transaction PIN' });
    }

    let numericAmount = parseFloat(amount);
    
    // TODO: Apply discount if it's the first transaction and signup_discount > 0
    // let finalAmount = numericAmount * (1 - userResult.rows[0].signup_discount / 100);
    // ... then clear the signup_discount field.
    
    // Check balance
    const walletResult = await pool.query('SELECT balance FROM wallets WHERE user_id = $1', [userId]);
    const currentBalance = parseFloat(walletResult.rows[0].balance);
    if (currentBalance < numericAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Use a transaction
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. Deduct from wallet
        await client.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [numericAmount, userId]);

        // 2. Record transaction
        await client.query(
          `INSERT INTO transactions (user_id, type, service_type, amount, details) VALUES ($1, $2, $3, $4, $5)`,
          [userId, 'debit', 'airtime', numericAmount, JSON.stringify({ network, phone, status: 'completed' })]
        );
        
        // 3. Clear signup discount if used (pseudo-logic)
        // if (userResult.rows[0].signup_discount > 0) {
        //   await client.query('UPDATE users SET signup_discount = 0 WHERE id = $1', [userId]);
        // }
        
        await client.query('COMMIT');

        res.json({
          success: true,
          message: `Airtime purchase successful! ₦${numericAmount} sent to ${phone}`,
          transaction: { type: 'airtime', amount: numericAmount, phone: phone, network: network }
        });

    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }

  } catch (error) {
    console.error('Airtime purchase error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// DATA PURCHASE (Modified for PIN)
app.post('/api/services/data', authenticateToken, async (req, res) => {
  try {
    const { network, phone, plan, amount, pin } = req.body;
    const userId = req.user.id;

    if (!network || !phone || !plan || !amount || !pin) {
      return res.status(400).json({ success: false, message: 'Network, phone, plan, amount, and PIN are required' });
    }
    
    // Verify PIN
    const userResult = await pool.query('SELECT pin FROM users WHERE id = $1', [userId]);
    const isPinValid = await bcrypt.compare(pin, userResult.rows[0].pin);
    if (!isPinValid) {
        return res.status(401).json({ success: false, message: 'Invalid transaction PIN' });
    }
    
    const numericAmount = parseFloat(amount);
    
    // Check balance
    const walletResult = await pool.query('SELECT balance FROM wallets WHERE user_id = $1', [userId]);
    const currentBalance = parseFloat(walletResult.rows[0].balance);
    if (currentBalance < numericAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    // Use a transaction
    const client = await pool.connect();
     try {
        await client.query('BEGIN');

        // 1. Deduct from wallet
        await client.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [numericAmount, userId]);

        // 2. Record transaction
        await client.query(
          `INSERT INTO transactions (user_id, type, service_type, amount, details) VALUES ($1, $2, $3, $4, $5)`,
          [userId, 'debit', 'data', numericAmount, JSON.stringify({ network, phone, plan, status: 'completed' })]
        );
        
        await client.query('COMMIT');
        
        res.json({
          success: true,
          message: `Data purchase successful! ${plan} data sent to ${phone}`,
          transaction: { type: 'data', amount: numericAmount, phone: phone, network: network, plan: plan }
        });

    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }

  } catch (error) {
    console.error('Data purchase error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// --- Admin Endpoints ---
const adminRouter = express.Router();

// 5A. ADMIN LOGIN
adminRouter.post('/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign(
                { admin: true, iat: Math.floor(Date.now() / 1000) },
                process.env.JWT_SECRET,
                { expiresIn: '8h' }
            );
            return res.json({ success: true, message: 'Admin login successful', token });
        } else {
            return res.status(401).json({ success: false, message: 'Invalid admin password' });
        }
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 3A. ADMIN: GENERATE REFERRAL CODES
adminRouter.post('/referral-codes', adminAuth, async (req, res) => {
    try {
        const { discountPercentage } = req.body;
        if (discountPercentage !== 5 && discountPercentage !== 10) {
            return res.status(400).json({ success: false, message: 'Discount must be 5 or 10' });
        }

        const code = "QT" + discountPercentage + "-" + crypto.randomBytes(3).toString('hex').toUpperCase();

        const result = await pool.query(
            `INSERT INTO referral_codes (code, discount_percentage, is_single_use)
             VALUES ($1, $2, true)
             RETURNING code`,
            [code, discountPercentage]
        );

        res.status(201).json({ success: true, code: result.rows[0].code });

    } catch (error) {
        console.error('Generate referral error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// 5B. ADMIN: SEND NOTIFICATIONS
adminRouter.post('/notifications', adminAuth, async (req, res) => {
    try {
        const { title, body, targetUser } = req.body; // targetUser from admin.html
        if (!title || !body) {
            return res.status(400).json({ success: false, message: 'Title and body are required' });
        }

        // 1. Store notification in DB
        // We store one notification for *all* users (null target_user_id)
        // The app will fetch this. A real system would be more complex.
        await pool.query(
            'INSERT INTO notifications (title, body) VALUES ($1, $2)',
            [title, body]
        );

        // 2. Send push notification via FCM
        const message = {
            notification: { title, body },
            topic: 'all_users' // Assumes all users are subscribed to this topic
        };

        try {
            const response = await admin.messaging().send(message);
            console.log('FCM message sent:', response);
            res.json({ success: true, message: 'Notification sent and stored successfully.' });
        } catch (fcmError) {
            console.error('FCM send error:', fcmError);
            res.status(500).json({ success: false, message: 'Failed to send push notification. Check Firebase Admin config.' });
        }

    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// GET NOTIFICATIONS (for the app)
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        // Fetches global notifications (target_user_id IS NULL)
        const result = await pool.query(
            `SELECT id, title, body, created_at, is_read 
             FROM notifications
             WHERE target_user_id IS NULL
             ORDER BY created_at DESC
             LIMIT 15`
            // In a real app, you'd also fetch user-specific notifications
            // AND (target_user_id = $1 OR target_user_id IS NULL)
        );

        // This is a simplified version. `is_read` would be per-user.
        res.json({ success: true, notifications: result.rows });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Mount the admin router
app.use('/api/admin', adminRouter);


// --- Error Handlers ---
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'API endpoint not found' });
});

app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', error);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// --- Start Server ---
const startServer = async () => {
  try {
    // Database initialization is now done by `init-db.js` via render.yaml
    
    const PORT = process.env.PORT || 10000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 QuickTop Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV}`);
      console.log(`🔗 Base URL: http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

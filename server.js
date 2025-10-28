const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin'); 
const sgMail = require('@sendgrid/mail'); 
const fs = require('fs'); 
const path = require('path'); 
require('dotenv').config();

// ⚡ FIX 1: Import the function via named destructuring { initDatabase }
const { initDatabase } = require('./init-db');

const app = express();

// --- Core Configuration and Middleware ---

app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes.'
});
app.use(limiter);

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ PostgreSQL connected successfully');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL connection error:', err);
});

// --- Firebase and SendGrid Setup ---

// Firebase Admin SDK Initialization (Secure Environment Variable Method)
const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
let firebaseAdminInitialized = false;

if (serviceAccountString) {
  try {
    const serviceAccount = JSON.parse(serviceAccountString);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
      // If you are using Realtime Database or Storage, add 'databaseURL' here
    });
    firebaseAdminInitialized = true;
    console.log('✅ Firebase Admin SDK initialized from environment variable');
  } catch (e) {
    console.error('❌ Error parsing FIREBASE_SERVICE_ACCOUNT_JSON:', e.message);
    console.error('   Push notifications will be disabled.');
  }
} else {
  console.warn('⚠️ FIREBASE_SERVICE_ACCOUNT_JSON environment variable not set. Push notifications will be disabled.');
}

// Set SendGrid API Key and Sender
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const SENDER_EMAIL = process.env.SENDGRID_VERIFIED_SENDER || 'contact.quicktop@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'quicktop_admin_pass_2025!';

// --- Utility Functions ---

const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateResetPinToken = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
const hashPin = async (pin) => bcrypt.hash(pin.toString(), 10);
const verifyPin = async (pin, hashedPin) => bcrypt.compare(pin.toString(), hashedPin);

const getEmailTemplate = (templateName, replacements = {}) => {
  try {
    let html = fs.readFileSync(path.join(__dirname, templateName), 'utf8');
    for (const [key, value] of Object.entries(replacements)) {
      html = html.replace(new RegExp(`{${key}}`, 'g'), value);
    }
    return html;
  } catch (error) {
    console.error(`❌ Error reading email template ${templateName}:`, error);
    return `<p>Error loading email content. Subject: ${templateName}</p>`;
  }
};

const sendEmail = async (to, subject, htmlContent) => {
  const msg = {
    to,
    from: SENDER_EMAIL,
    subject,
    html: htmlContent,
  };
  try {
    await sgMail.send(msg);
    console.log(`✉️ Email sent to ${to}: ${subject}`);
    return true;
  } catch (error) {
    console.error('❌ SendGrid Email Error:', error.response ? JSON.stringify(error.response.body.errors) : error.message);
    return false;
  }
};

const sendPushNotification = async (token, title, body) => {
    if (!firebaseAdminInitialized) {
        console.warn('Push notification failed: Firebase Admin SDK not initialized.');
        return false;
    }
    const message = {
        notification: { title, body },
        token: token,
    };
    try {
        const response = await admin.messaging().send(message);
        console.log('Successfully sent message:', response);
        return true;
    } catch (error) {
        console.error('Error sending push notification:', error);
        return false;
    }
};

// --- Middleware ---

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token.'
      });
    }
    req.user = user;
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }
    next();
};

// --- API Routes ---

// Simple test route
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 QuickTop Backend API is running!',
    timestamp: new Date().toISOString(),
    // Added endpoint list for easy reference
    endpoints: {
      auth: ['/api/auth/register', '/api/auth/login', '/api/auth/verify-email', '/api/auth/set-pin'],
      user: ['/api/user/profile', '/api/user/transactions'],
      services: ['/api/services/airtime'],
      admin: ['/api/admin/login', '/api/admin/referral-codes', '/api/admin/notifications']
    }
  });
});

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
  // Added 'country' to reflect init-db.js schema
  const { name, email, phone, country, password, referral_code } = req.body;

  if (!name || !email || !phone || !password || !country) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required (name, email, phone, country, password).'
    });
  }

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1 OR phone = $2', [email, phone]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or phone number already exists.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // PIN is set later, but schema requires a value. Use empty string or hash a default/placeholder.
    const defaultPin = await hashPin('0000'); 
    const verification_code = generateVerificationCode(); 

    const result = await pool.query(
      // Updated query to include 'country' and 'pin'
      `INSERT INTO users (name, email, phone, country, password, pin, is_verified, verification_code)
       VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7) RETURNING id, name, email, phone`,
      [name, email, phone, country, hashedPassword, defaultPin, verification_code]
    );

    const user = result.rows[0];

    // NEW: Create wallet for user
    await pool.query('INSERT INTO wallets (user_id) VALUES ($1)', [user.id]);
    
    // NEW: Send verification email
    const htmlContent = getEmailTemplate('emailver.html', { 
        user_name: user.name, 
        VERIFICATION_CODE: verification_code 
    });
    
    const emailSent = await sendEmail(user.email, 'QuickTop: Verify Your Account', htmlContent);

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email for the verification code.',
      user: { id: user.id, email: user.email, phone: user.phone },
      emailSent: emailSent
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.post('/api/auth/verify-email', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ success: false, message: 'Email and verification code are required.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, is_verified, verification_code FROM users WHERE email = $1',
            [email]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        if (user.is_verified) {
            return res.status(400).json({ success: false, message: 'Account already verified.' });
        }

        if (user.verification_code !== code) {
            return res.status(401).json({ success: false, message: 'Invalid verification code.' });
        }

        // Verification successful: update user status
        await pool.query(
            'UPDATE users SET is_verified = TRUE, verification_code = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        // Generate JWT token (Only after verification)
        const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN || '30d'
        });

        // Send welcome email
        const welcomeHtml = getEmailTemplate('emailwel.html', { user_name: user.name });
        await sendEmail(email, 'Welcome to QuickTop!', welcomeHtml);

        res.json({
            success: true,
            message: 'Email verified successfully. Welcome to QuickTop!',
            token: token
        });

    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/resend-code', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, is_verified FROM users WHERE email = $1',
            [email]
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        if (user.is_verified) {
            return res.status(400).json({ success: false, message: 'Account is already verified. Please login.' });
        }

        const new_code = generateVerificationCode();
        
        await pool.query(
            'UPDATE users SET verification_code = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [new_code, user.id]
        );

        const htmlContent = getEmailTemplate('emailver.html', { 
            user_name: user.name, 
            VERIFICATION_CODE: new_code 
        });
        
        const emailSent = await sendEmail(email, 'QuickTop: New Verification Code', htmlContent);

        res.json({
            success: true,
            message: 'A new verification code has been sent to your email.',
            emailSent: emailSent
        });

    } catch (error) {
        console.error('Resend code error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
  const { emailOrPhone, password, fcm_token } = req.body;

  if (!emailOrPhone || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email/Phone and password are required.'
    });
  }

  try {
    // Select the 'pin' column to check if a PIN is set
    const result = await pool.query(
      'SELECT id, email, password, is_verified, pin FROM users WHERE email = $1 OR phone = $1',
      [emailOrPhone]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email/phone or password.'
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email/phone or password.'
      });
    }

    if (!user.is_verified) {
        return res.status(403).json({
            success: false,
            message: 'Account not verified. Please verify your email first.'
        });
    }
    
    // NEW: Update FCM token if provided (assuming this column exists)
    if (fcm_token) {
        await pool.query('UPDATE users SET fcm_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [fcm_token, user.id]);
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '30d'
    });

    res.json({
      success: true,
      message: 'Login successful.',
      token: token,
      // Check for the 'pin' column's value
      pin_is_set: user.pin !== null && user.pin !== '0000' // Assuming default '0000' is unset
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// --- PIN Management Routes (Requires Auth) ---

app.post('/api/auth/set-pin', authenticateToken, async (req, res) => {
    const { pin } = req.body;

    if (!pin || pin.length !== 4 || isNaN(pin)) {
        return res.status(400).json({ success: false, message: 'A 4-digit numeric PIN is required.' });
    }

    try {
        const hashedPin = await hashPin(pin);
        
        // Use the 'pin' column name
        await pool.query(
            'UPDATE users SET pin = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id',
            [hashedPin, req.user.id]
        );
        
        res.json({ success: true, message: 'Transaction PIN set successfully!' });

    } catch (error) {
        console.error('Set PIN error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/forgot-pin', authenticateToken, async (req, res) => {
    try {
        const token = generateResetPinToken();
        const resetPinLink = `https://your-mobile-app.com/reset-pin?token=${token}`; // Adjust to your mobile app deep link

        // Use 'pin_reset_code' and 'pin_reset_expires'
        await pool.query(
            'UPDATE users SET pin_reset_code = $1, pin_reset_expires = NOW() + INTERVAL \'1 hour\' WHERE id = $2 RETURNING name, email',
            [token, req.user.id]
        );

        const user = (await pool.query('SELECT name, email FROM users WHERE id = $1', [req.user.id])).rows[0];

        const htmlContent = getEmailTemplate('forgotpin.html', {
            user_name: user.name,
            RESET_PIN_LINK: resetPinLink
        });
        
        const emailSent = await sendEmail(user.email, 'QuickTop: Transaction PIN Reset', htmlContent);

        res.json({
            success: true,
            message: 'Transaction PIN reset link has been sent to your registered email.',
            emailSent: emailSent
        });

    } catch (error) {
        console.error('Forgot PIN error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/reset-pin', authenticateToken, async (req, res) => {
    const { token, newPin } = req.body;

    if (!token || !newPin || newPin.length !== 4 || isNaN(newPin)) {
        return res.status(400).json({ success: false, message: 'Valid token and new 4-digit PIN are required.' });
    }

    try {
        // Use 'pin_reset_code' and 'pin_reset_expires' for lookup
        const result = await pool.query(
            `SELECT id FROM users 
             WHERE id = $1 
               AND pin_reset_code = $2 
               AND pin_reset_expires > NOW()`,
            [req.user.id, token]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid or expired reset token.' });
        }

        const hashedPin = await hashPin(newPin);
        
        // Use 'pin', 'pin_reset_code', and 'pin_reset_expires' for update
        await pool.query(
            `UPDATE users 
             SET pin = $1, pin_reset_code = NULL, pin_reset_expires = NULL, updated_at = CURRENT_TIMESTAMP 
             WHERE id = $2`,
            [hashedPin, req.user.id]
        );
        
        res.json({ success: true, message: 'Transaction PIN reset successfully!' });

    } catch (error) {
        console.error('Reset PIN error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// --- USER ROUTES ---

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.name, u.email, u.phone, u.country, u.created_at, u.is_verified, 
         w.balance, u.pin IS NOT NULL AND u.pin != $2 AS pin_is_set
       FROM users u
       JOIN wallets w ON u.id = w.user_id
       WHERE u.id = $1`,
      [req.user.id, await hashPin('0000')] // Check if pin is set and not the default value
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    const user = result.rows[0];

    res.json({
      success: true,
      user: {
        name: user.name,
        email: user.email,
        phone: user.phone,
        country: user.country,
        balance: user.balance,
        pin_is_set: user.pin_is_set,
        is_verified: user.is_verified,
        member_since: user.created_at,
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.get('/api/user/transactions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, type, service_type, amount, details, created_at 
       FROM transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [req.user.id]
    );

    res.json({
      success: true,
      transactions: result.rows
    });

  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// --- SERVICES ROUTES ---

app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  const { amount, phone_number, network, pin } = req.body;

  if (!amount || !phone_number || !network || !pin) {
    return res.status(400).json({ success: false, message: 'Amount, phone number, network, and PIN are required.' });
  }

  const transactionAmount = parseFloat(amount);
  if (isNaN(transactionAmount) || transactionAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid transaction amount.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Verify PIN
    // Select the 'pin' column
    const pinCheck = await client.query('SELECT pin, fcm_token FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = pinCheck.rows[0];

    // Check against the 'pin' column
    if (!user || !user.pin || user.pin === await hashPin('0000')) {
      await client.query('ROLLBACK');
      return res.status(403).json({ success: false, message: 'Transaction PIN not set. Please set your PIN first.' });
    }

    // Compare against the 'pin' column's hash
    const pinMatch = await verifyPin(pin, user.pin);

    if (!pinMatch) {
      await client.query('ROLLBACK');
      return res.status(401).json({ success: false, message: 'Invalid transaction PIN.' });
    }
    
    // 2. Check Wallet Balance
    const walletResult = await client.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [req.user.id]);
    let currentBalance = parseFloat(walletResult.rows[0].balance);

    if (currentBalance < transactionAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
    }

    // 3. Process Transaction (Simulation)
    // In a real app, this is where you'd call a third-party API (e.g., VTU provider)
    const success = Math.random() > 0.1; // Simulate a 90% success rate

    if (success) {
      const newBalance = currentBalance - transactionAmount;

      // 4. Update Wallet Balance
      await client.query(
        'UPDATE wallets SET balance = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2',
        [newBalance, req.user.id]
      );

      // 5. Record Transaction
      const transactionDetails = { phone_number, network, status: 'Success' };
      await client.query(
        `INSERT INTO transactions (user_id, type, service_type, amount, details)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.user.id, 'Debit', 'Airtime Purchase', transactionAmount, transactionDetails]
      );
      
      // 6. Send Push Notification
      if (user.fcm_token) {
          sendPushNotification(user.fcm_token, 'Airtime Purchased!', `You successfully bought ₦${transactionAmount} for ${phone_number}.`);
      }


      await client.query('COMMIT');
      res.json({
        success: true,
        message: `Successfully purchased ₦${transactionAmount} airtime for ${phone_number}.`,
        new_balance: newBalance,
      });
    } else {
      // Simulation of a third-party failure
      await client.query('ROLLBACK');
      res.status(503).json({ success: false, message: 'Service provider error. Transaction failed.' });
    }

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Airtime transaction error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during transaction.' });
  } finally {
    client.release();
  }
});


// --- ADMIN ROUTES ---

app.post('/api/admin/login', async (req, res) => {
    const { password } = req.body;

    if (password === ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ success: true, message: 'Admin login successful.', token: token });
    }

    res.status(401).json({ success: false, message: 'Invalid admin password.' });
});

app.post('/api/admin/referral-codes', authenticateToken, authorizeAdmin, async (req, res) => {
    // Note: The new schema for referral_codes has is_single_use, owner_user_id
    const { code, discount_percentage, is_single_use, expiry_date, owner_user_id } = req.body;
    
    if (!code || !discount_percentage) {
        return res.status(400).json({ success: false, message: 'Code and discount_percentage are required.' });
    }
    
    try {
        await pool.query(
            // Updated to reflect new schema columns
            `INSERT INTO referral_codes (code, discount_percentage, is_single_use, expiry_date, owner_user_id)
             VALUES ($1, $2, $3, $4, $5)`,
            [code, discount_percentage, is_single_use || false, expiry_date || null, owner_user_id || null]
        );
        
        res.status(201).json({ success: true, message: `Referral code ${code} created successfully.` });

    } catch (error) {
        if (error.code === '23505') { // PostgreSQL unique violation error
            return res.status(409).json({ success: false, message: 'Referral code already exists.' });
        }
        console.error('Admin create referral error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/admin/notifications', authenticateToken, authorizeAdmin, async (req, res) => {
    const { title, body, target_user_id } = req.body;

    if (!title || !body) {
        return res.status(400).json({ success: false, message: 'Notification title and body are required.' });
    }
    
    if (!firebaseAdminInitialized) {
        return res.status(503).json({ success: false, message: 'Push notifications service is not active (Firebase Admin SDK not initialized).' });
    }

    try {
        let tokens;
        if (target_user_id) {
            // Send to a single user (assuming fcm_token is added to the users table)
            const result = await pool.query('SELECT fcm_token FROM users WHERE id = $1 AND fcm_token IS NOT NULL', [target_user_id]);
            tokens = result.rows.map(row => row.fcm_token);
            if (tokens.length === 0) {
                 return res.status(404).json({ success: false, message: `User with ID ${target_user_id} not found or has no FCM token.` });
            }
        } else {
            // Send to all users
            const result = await pool.query('SELECT fcm_token FROM users WHERE fcm_token IS NOT NULL');
            tokens = result.rows.map(row => row.fcm_token);
        }

        if (tokens.length === 0) {
            return res.status(404).json({ success: false, message: 'No valid FCM tokens found for the target audience.' });
        }

        const message = {
            notification: { title, body },
            tokens: tokens, // Use sendMulticast for multiple tokens
        };
        
        const response = await admin.messaging().sendEachForMulticast(message);
        
        res.json({ 
            success: true, 
            message: `Successfully sent notification to ${response.successCount} of ${tokens.length} users.`,
            response: response
        });

    } catch (error) {
        console.error('Admin notification error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// --- ERROR HANDLERS ---

// 404 handler - MUST BE LAST BEFORE GLOBAL HANDLER
app.use('*', (req, res) => {
  console.log('❌ Route not found:', req.originalUrl);
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    requested: req.originalUrl
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', error);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// Initialize database and start server
const startServer = async () => {
  try {
    // ⚡ FIX 2: Call the function without arguments, since init-db.js manages its own pool.
    // This will run the schema initialization code
    await initDatabase(); 
    
    const PORT = process.env.PORT || 10000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 QuickTop Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV}`);
    });
  } catch (error) {
    console.error('Server failed to start:', error);
    process.exit(1);
  }
};

startServer();

// End of server.js

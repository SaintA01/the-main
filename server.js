const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// PostgreSQL connection pool with enhanced configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test database connection
const testConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('✅ PostgreSQL connected successfully');
    
    // Test basic query
    const result = await client.query('SELECT NOW()');
    console.log('📊 Database time:', result.rows[0].now);
    
    client.release();
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    console.log('💡 Make sure your DATABASE_URL is correctly set in environment variables');
  }
};

testConnection();

// Enhanced middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  }
});
app.use(limiter);

// JWT middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required' 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const userResult = await pool.query(
      'SELECT id, name, email, phone, created_at FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    console.error('JWT verification error:', error);
    return res.status(403).json({ 
      success: false, 
      message: 'Invalid or expired token' 
    });
  }
};

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    
    res.json({ 
      success: true, 
      message: 'QuickTop API is running!', 
      timestamp: new Date().toISOString(),
      database: 'connected',
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Service unhealthy - database connection failed',
      timestamp: new Date().toISOString(),
      database: 'disconnected'
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Welcome to QuickTop Backend API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth/*',
      services: '/api/services/*',
      wallet: '/api/wallet/*',
      health: '/api/health'
    }
  });
});

// Signup endpoint
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Validation
    if (!name || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required: name, email, phone, password'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    if (!/^(080|081|070|090|091)\d{8}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid Nigerian phone number'
      });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR phone = $2',
      [email, phone]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or phone already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, name, email, phone, created_at`,
      [name, email, phone, hashedPassword]
    );

    const user = result.rows[0];

    // Create wallet for user with initial balance
    await pool.query(
      'INSERT INTO wallets (user_id, balance) VALUES ($1, $2)',
      [user.id, 5000] // Initial balance for demo
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET || 'fallback-secret-key-change-in-production', 
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = result.rows[0];

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET || 'fallback-secret-key-change-in-production',
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

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
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// Get current user profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get wallet balance
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }

    res.json({
      success: true,
      balance: parseFloat(result.rows[0].balance)
    });

  } catch (error) {
    console.error('Get balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Fund wallet endpoint
app.post('/api/wallet/fund', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required'
      });
    }

    const result = await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 RETURNING balance',
      [amount, req.user.id]
    );

    res.json({
      success: true,
      message: 'Wallet funded successfully',
      balance: parseFloat(result.rows[0].balance)
    });

  } catch (error) {
    console.error('Fund wallet error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Airtime purchase endpoint
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  try {
    const { network, phone, amount } = req.body;

    // Validation
    if (!network || !phone || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Network, phone, and amount are required'
      });
    }

    if (!['mtn', 'glo', 'airtel', '9mobile'].includes(network)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid network provider'
      });
    }

    if (!/^(080|081|070|090|091)\d{8}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number'
      });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid amount'
      });
    }

    // Check wallet balance
    const walletResult = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    if (walletResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }

    const currentBalance = parseFloat(walletResult.rows[0].balance);
    if (currentBalance < numericAmount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Deduct from wallet
    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2',
      [numericAmount, req.user.id]
    );

    // Record transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, service_type, amount, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        'debit',
        'airtime',
        numericAmount,
        JSON.stringify({
          network,
          phone,
          amount: numericAmount,
          status: 'completed',
          timestamp: new Date().toISOString()
        })
      ]
    );

    res.json({
      success: true,
      message: `Airtime purchase successful! ₦${numericAmount} sent to ${phone}`,
      transaction: {
        type: 'airtime',
        amount: numericAmount,
        phone: phone,
        network: network,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Airtime purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during airtime purchase'
    });
  }
});

// Data purchase endpoint
app.post('/api/services/data', authenticateToken, async (req, res) => {
  try {
    const { network, phone, plan, amount } = req.body;

    // Validation
    if (!network || !phone || !plan || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Network, phone, plan, and amount are required'
      });
    }

    if (!['mtn', 'glo', 'airtel', '9mobile'].includes(network)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid network provider'
      });
    }

    if (!/^(080|081|070|090|091)\d{8}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number'
      });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid amount'
      });
    }

    // Check wallet balance
    const walletResult = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    if (walletResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }

    const currentBalance = parseFloat(walletResult.rows[0].balance);
    if (currentBalance < numericAmount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Deduct from wallet
    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2',
      [numericAmount, req.user.id]
    );

    // Record transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, service_type, amount, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        'debit',
        'data',
        numericAmount,
        JSON.stringify({
          network,
          phone,
          plan,
          amount: numericAmount,
          status: 'completed',
          timestamp: new Date().toISOString()
        })
      ]
    );

    res.json({
      success: true,
      message: `Data purchase successful! ${plan} data sent to ${phone}`,
      transaction: {
        type: 'data',
        amount: numericAmount,
        phone: phone,
        network: network,
        plan: plan,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Data purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during data purchase'
    });
  }
});

// Get user transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
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

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 QuickTop Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
});

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware - MUST COME FIRST
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
  max: 100
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

// Simple test route - ADD THIS TO VERIFY SERVER IS RUNNING
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 QuickTop Backend API is running!',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/api/health',
      signup: '/api/auth/signup',
      login: '/api/auth/login',
      profile: '/api/auth/me',
      balance: '/api/wallet/balance',
      airtime: '/api/services/airtime',
      data: '/api/services/data'
    }
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    res.json({
      success: true,
      message: '✅ API is healthy',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: '❌ API is unhealthy',
      database: 'disconnected',
      error: error.message
    });
  }
});

// Initialize database tables
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database tables...');
    
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create wallets table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        balance DECIMAL(12,2) DEFAULT 5000.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id)
      )
    `);

    // Create transactions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(20) NOT NULL,
        service_type VARCHAR(50) NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables initialized successfully!');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
  }
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    
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
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// SIGNUP ENDPOINT - FIXED
app.post('/api/auth/signup', async (req, res) => {
  console.log('📝 Signup request received:', req.body);
  
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

    // Check if user exists
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
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const userResult = await pool.query(
      `INSERT INTO users (name, email, phone, password) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, name, email, phone, created_at`,
      [name, email, phone, hashedPassword]
    );

    const user = userResult.rows[0];

    // Create wallet
    await pool.query(
      'INSERT INTO wallets (user_id, balance) VALUES ($1, $2)',
      [user.id, 5000]
    );

    // Generate token
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '30d' }
    );

    console.log('✅ User created successfully:', user.email);
    
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
    console.error('❌ Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
});

// LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
  console.log('🔐 Login request received:', req.body.email);
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = userResult.rows[0];

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '30d' }
    );

    console.log('✅ Login successful:', user.email);
    
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
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// PROFILE ENDPOINT
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

// WALLET BALANCE ENDPOINT
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      success: true,
      balance: parseFloat(result.rows[0]?.balance || 0)
    });

  } catch (error) {
    console.error('Get balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// FUND WALLET ENDPOINT
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

// AIRTIME PURCHASE ENDPOINT
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  try {
    const { network, phone, amount } = req.body;

    if (!network || !phone || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Network, phone, and amount are required'
      });
    }

    const numericAmount = parseFloat(amount);
    
    // Check balance
    const walletResult = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

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
        JSON.stringify({ network, phone, amount: numericAmount, status: 'completed' })
      ]
    );

    res.json({
      success: true,
      message: `Airtime purchase successful! ₦${numericAmount} sent to ${phone}`,
      transaction: {
        type: 'airtime',
        amount: numericAmount,
        phone: phone,
        network: network
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

// DATA PURCHASE ENDPOINT
app.post('/api/services/data', authenticateToken, async (req, res) => {
  try {
    const { network, phone, plan, amount } = req.body;

    if (!network || !phone || !plan || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Network, phone, plan, and amount are required'
      });
    }

    const numericAmount = parseFloat(amount);
    
    // Check balance
    const walletResult = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

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
        JSON.stringify({ network, phone, plan, amount: numericAmount, status: 'completed' })
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
        plan: plan
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

// TRANSACTIONS ENDPOINT
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

// 404 handler - MUST BE LAST
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
    await initializeDatabase();
    
    const PORT = process.env.PORT || 10000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 QuickTop Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 Base URL: http://localhost:${PORT}`);
      console.log(`🏥 Health check: http://localhost:${PORT}/api/health`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, initDB } = require('./database');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Initialize database
initDB();

// Auth Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userResult = await pool.query(
      'SELECT id, name, email, phone FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(403).json({ message: 'User not found' });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Routes
app.get('/api', (req, res) => {
  res.json({ 
    message: 'QuickTop API is running with PostgreSQL!',
    version: '1.0.0',
    database: 'PostgreSQL'
  });
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const userResult = await pool.query(
      'INSERT INTO users (name, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email, phone',
      [name, email, phone, hashedPassword]
    );

    // Create wallet for user
    await pool.query(
      'INSERT INTO wallets (user_id, balance) VALUES ($1, $2)',
      [userResult.rows[0].id, 10000.00]
    );

    const token = jwt.sign(
      { userId: userResult.rows[0].id, email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: userResult.rows[0]
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    res.json({
      message: 'Login successful',
      token,
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Get wallet balance
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const balanceResult = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    const balance = balanceResult.rows[0]?.balance || 0;
    
    res.json({ 
      balance: parseFloat(balance),
      currency: 'NGN'
    });
  } catch (error) {
    console.error('Wallet balance error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Buy Airtime
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const { network, phone, amount } = req.body;

    if (!network || !phone || !amount) {
      return res.status(400).json({ message: 'Network, phone, and amount are required' });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }

    // Check balance
    const balanceResult = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [req.user.id]
    );

    const currentBalance = parseFloat(balanceResult.rows[0]?.balance || 0);
    
    if (currentBalance < numericAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Update balance
    const newBalance = currentBalance - numericAmount;
    await client.query(
      'UPDATE wallets SET balance = $1 WHERE user_id = $2',
      [newBalance, req.user.id]
    );

    // Record transaction
    const transactionResult = await client.query(
      `INSERT INTO transactions (user_id, type, network, phone, amount) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, 'airtime', network, phone, numericAmount]
    );

    await client.query('COMMIT');

    res.json({
      message: `Airtime purchase successful! ${numericAmount} Naira ${network} airtime sent to ${phone}`,
      transaction: transactionResult.rows[0],
      newBalance
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Airtime purchase error:', error);
    res.status(500).json({ message: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Buy Data
app.post('/api/services/data', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const { network, phone, plan, amount } = req.body;

    if (!network || !phone || !plan || !amount) {
      return res.status(400).json({ message: 'Network, phone, plan, and amount are required' });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }

    // Check balance
    const balanceResult = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [req.user.id]
    );

    const currentBalance = parseFloat(balanceResult.rows[0]?.balance || 0);
    
    if (currentBalance < numericAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Update balance
    const newBalance = currentBalance - numericAmount;
    await client.query(
      'UPDATE wallets SET balance = $1 WHERE user_id = $2',
      [newBalance, req.user.id]
    );

    // Record transaction
    const transactionResult = await client.query(
      `INSERT INTO transactions (user_id, type, network, phone, plan, amount) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.user.id, 'data', network, phone, plan, numericAmount]
    );

    await client.query('COMMIT');

    res.json({
      message: `Data purchase successful! ${plan} ${network} data sent to ${phone}`,
      transaction: transactionResult.rows[0],
      newBalance
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Data purchase error:', error);
    res.status(500).json({ message: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Get transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const transactionsResult = await pool.query(
      `SELECT * FROM transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [req.user.id]
    );

    res.json({ transactions: transactionsResult.rows });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 QuickTop PostgreSQL backend running on port ${PORT}`);
});

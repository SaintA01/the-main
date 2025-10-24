const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// Debug environment variables
console.log('🔧 Environment Check:');
console.log('- DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('- NODE_ENV:', process.env.NODE_ENV);

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is missing!');
  console.log('Please set DATABASE_URL in Railway environment variables');
}

// Database connection with better error handling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Add connection timeout
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// Test database connection on startup
const testConnection = async () => {
  try {
    console.log('🔄 Testing database connection...');
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    console.log('✅ Database connected successfully:', result.rows[0].now);
    client.release();
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('💡 DATABASE_URL should look like: postgresql://user:pass@host:port/database');
    return false;
  }
};

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Health check (no database required)
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 QuickTop Backend is Running!',
    database: process.env.DATABASE_URL ? 'Configured' : 'Missing',
    status: 'OK'
  });
});

// Test database connection endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time, version() as version');
    res.json({
      success: true,
      message: 'Database connected!',
      time: result.rows[0].time,
      version: result.rows[0].version
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      error: error.message,
      help: 'Check DATABASE_URL environment variable'
    });
  }
});

// Simple in-memory demo mode (remove later)
let demoUsers = [];
let demoWallets = {};

// Demo signup (remove when database works)
app.post('/api/demo/signup', (req, res) => {
  const { name, email, phone, password } = req.body;
  
  const user = {
    id: Date.now(),
    name,
    email, 
    phone,
    createdAt: new Date().toISOString()
  };
  
  demoUsers.push(user);
  demoWallets[user.id] = 10000;
  
  const token = jwt.sign({ userId: user.id, email }, JWT_SECRET);
  
  res.json({
    message: 'Demo account created (in-memory)',
    token,
    user
  });
});

// Demo login (remove when database works)
app.post('/api/demo/login', (req, res) => {
  const { email, password } = req.body;
  
  const user = demoUsers.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }
  
  const token = jwt.sign({ userId: user.id, email }, JWT_SECRET);
  
  res.json({
    message: 'Demo login successful',
    token,
    user
  });
});

// Initialize and start server
const startServer = async () => {
  const PORT = process.env.PORT || 3000;
  
  // Test database connection
  const dbConnected = await testConnection();
  
  if (!dbConnected) {
    console.log('⚠️  Starting in DEMO MODE (no database)');
    console.log('💡 Use /api/demo/signup and /api/demo/login for testing');
  }
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Health check: http://localhost:${PORT}/`);
    console.log(`🔗 Test database: http://localhost:${PORT}/api/test-db`);
  });
};

startServer();

module.exports = app;

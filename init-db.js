const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const initDatabase = async () => {
  try {
    console.log('🔄 Initializing QuickTop database schema (v2)...');

    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        country VARCHAR(100) NOT NULL,
        password VARCHAR(255) NOT NULL,
        pin VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT false,
        verification_code VARCHAR(255),
        verification_expires TIMESTAMP,
        pin_reset_code VARCHAR(255),
        pin_reset_expires TIMESTAMP,
        signup_discount DECIMAL(5, 2) DEFAULT 0.00,
        referred_by_code_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create wallets table (default balance is 0)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        balance DECIMAL(12,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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

    // Create referral codes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS referral_codes (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        discount_percentage DECIMAL(5, 2) NOT NULL,
        is_single_use BOOLEAN NOT NULL DEFAULT true,
        is_used BOOLEAN DEFAULT false,
        expiry_date TIMESTAMP,
        owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Add foreign key constraint for users.referred_by_code_id
    await pool.query(`
      ALTER TABLE users
      ADD CONSTRAINT fk_referred_by_code
      FOREIGN KEY (referred_by_code_id) 
      REFERENCES referral_codes(id) 
      ON DELETE SET NULL;
    `).catch(e => {
        // Ignore error if constraint already exists
        if (e.code !== '42710') console.error('FK constraint error:', e.message);
    });

    // Create notifications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        body TEXT NOT NULL,
        target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_referral_codes_code ON referral_codes(code)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_referral_codes_owner ON referral_codes(owner_user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(target_user_id)');

    console.log('✅ Database initialized successfully!');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
};

module.exports = { initDatabase };

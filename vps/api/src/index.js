const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection pool
const pool = new Pool({
  user: process.env.DB_USER || 'vpnmanager',
  password: process.env.DB_PASSWORD || 'your_secure_password_here',
  host: process.env.DB_HOST || 'postgres',
  database: process.env.DB_NAME || 'vpnmanager_db',
  port: process.env.DB_PORT || 5432,
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully:', res.rows[0].now);
  }
});

// Hello World route
app.get('/', (req, res) => {
  res.json({ message: 'Hello World from VPN Manager API' });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Simple database test endpoint
app.get('/db-test', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM users');
    res.json({ 
      message: 'Database connection successful',
      userCount: result.rows[0].count
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Database connection failed',
      error: error.message 
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`API server running on port ${port}`);
});

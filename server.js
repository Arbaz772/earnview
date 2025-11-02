// server.js - PostgreSQL Version with 500 ads daily limit
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// PostgreSQL connection pool
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'earnview',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'earnview',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  }
  console.log('✅ PostgreSQL connected successfully at', res.rows[0].now);
});

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later'
});

const adViewLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 2,
  message: 'Please wait before watching another ad'
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.userId = user.userId;
    next();
  });
};

// ============================================
// AUTH ENDPOINTS
// ============================================

app.post('/api/auth/register', [
  body('username').isLength({ min: 3, max: 50 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password, referralCode } = req.body;

  try {
    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userReferralCode = username.substring(0, 4).toUpperCase() + 
                             Math.random().toString(36).substring(2, 6).toUpperCase();

    let referrerId = null;
    if (referralCode) {
      const referrer = await pool.query(
        'SELECT id FROM users WHERE referral_code = $1',
        [referralCode]
      );
      if (referrer.rows.length > 0) {
        referrerId = referrer.rows[0].id;
      }
    }

    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, referral_code, referred_by) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [username, email, passwordHash, userReferralCode, referrerId]
    );

    const token = jwt.sign(
      { userId: result.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: result.rows[0].id,
        username,
        email,
        referralCode: userReferralCode
      }
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').exists()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT id, username, email, password_hash, status FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.status === 'suspended') {
      return res.status(403).json({ error: 'Account suspended' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================================
// USER ENDPOINTS
// ============================================

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, balance, total_earned, referral_code, paypal_email, created_at FROM users WHERE id = $1',
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const adCount = await pool.query(
      'SELECT COUNT(*) as count FROM ad_views WHERE user_id = $1 AND DATE(created_at) = CURRENT_DATE',
      [req.userId]
    );

    const user = result.rows[0];
    user.adsWatchedToday = parseInt(adCount.rows[0].count);
    user.balance = parseFloat(user.balance);
    user.total_earned = parseFloat(user.total_earned);

    res.json({ success: true, user });

  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/api/user/paypal', authenticateToken, [
  body('paypalEmail').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    await pool.query(
      'UPDATE users SET paypal_email = $1 WHERE id = $2',
      [req.body.paypalEmail, req.userId]
    );

    res.json({ success: true, message: 'PayPal email updated' });

  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// ============================================
// AD VIEWING ENDPOINTS
// ============================================

app.post('/api/ads/credit', adViewLimiter, authenticateToken, async (req, res) => {
  const { adType } = req.body;
  const userId = req.userId;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT status, balance FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0 || userResult.rows[0].status !== 'active') {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Account not active' });
    }

    // Check daily limit - CHANGED TO 500
    const todayCount = await client.query(
      'SELECT COUNT(*) as count FROM ad_views WHERE user_id = $1 AND DATE(created_at) = CURRENT_DATE',
      [userId]
    );

    if (parseInt(todayCount.rows[0].count) >= 500) {
      await client.query('ROLLBACK');
      return res.status(429).json({ error: 'Daily limit reached (500 ads)' });
    }

    const recentViews = await client.query(
      "SELECT COUNT(*) as count FROM ad_views WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 seconds'",
      [userId]
    );

    if (parseInt(recentViews.rows[0].count) > 0) {
      await client.query('ROLLBACK');
      return res.status(429).json({ error: 'Please wait 30 seconds between ads' });
    }

    const userEarning = 0.05;
    const platformRevenue = 0.10;
    const profit = platformRevenue - userEarning;

    await client.query(
      'UPDATE users SET balance = balance + $1, total_earned = total_earned + $2, last_ad_date = CURRENT_DATE WHERE id = $3',
      [userEarning, userEarning, userId]
    );

    await client.query(
      'INSERT INTO ad_views (user_id, ad_type, earning, revenue, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, adType || 'video', userEarning, platformRevenue, ip, userAgent]
    );

    await client.query(
      `INSERT INTO daily_revenue (date, ad_views, revenue, paid_out, profit, active_users) 
       VALUES (CURRENT_DATE, 1, $1, $2, $3, 1) 
       ON CONFLICT (date) DO UPDATE SET 
       ad_views = daily_revenue.ad_views + 1, 
       revenue = daily_revenue.revenue + $1, 
       paid_out = daily_revenue.paid_out + $2, 
       profit = daily_revenue.profit + $3`,
      [platformRevenue, userEarning, profit]
    );

    const referrerResult = await client.query(
      'SELECT referred_by FROM users WHERE id = $1',
      [userId]
    );

    if (referrerResult.rows[0].referred_by) {
      const referralBonus = userEarning * 0.10;
      await client.query(
        'UPDATE users SET balance = balance + $1 WHERE id = $2',
        [referralBonus, referrerResult.rows[0].referred_by]
      );
      await client.query(
        'INSERT INTO referral_earnings (referrer_id, referred_id, earning) VALUES ($1, $2, $3)',
        [referrerResult.rows[0].referred_by, userId, referralBonus]
      );
    }

    await client.query('COMMIT');

    const updated = await pool.query(
      'SELECT balance, total_earned FROM users WHERE id = $1',
      [userId]
    );

    res.json({
      success: true,
      earned: userEarning,
      balance: parseFloat(updated.rows[0].balance),
      totalEarned: parseFloat(updated.rows[0].total_earned),
      adsWatchedToday: parseInt(todayCount.rows[0].count) + 1,
      dailyLimit: 500  // CHANGED TO 500
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Credit error:', err);
    res.status(500).json({ error: 'Failed to credit ad view' });
  } finally {
    client.release();
  }
});

// ============================================
// WITHDRAWAL ENDPOINTS
// ============================================

app.post('/api/withdraw/request', authenticateToken, async (req, res) => {
  const { method, paypalEmail } = req.body;
  const userId = req.userId;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT balance, paypal_email FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }

    const balance = parseFloat(userResult.rows[0].balance);
    const savedPaypalEmail = userResult.rows[0].paypal_email;

    if (balance < 5.00) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Minimum withdrawal is $5.00' });
    }

    const pending = await client.query(
      "SELECT COUNT(*) as count FROM withdrawals WHERE user_id = $1 AND status = 'pending'",
      [userId]
    );

    if (parseInt(pending.rows[0].count) > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'You have a pending withdrawal' });
    }

    const emailToUse = paypalEmail || savedPaypalEmail;
    if (!emailToUse && method === 'paypal') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'PayPal email required' });
    }

    await client.query(
      'UPDATE users SET balance = 0 WHERE id = $1',
      [userId]
    );

    await client.query(
      'INSERT INTO withdrawals (user_id, amount, method, paypal_email, status) VALUES ($1, $2, $3, $4, $5)',
      [userId, balance, method, emailToUse, 'pending']
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Withdrawal request submitted. Processing within 24-48 hours.',
      amount: balance
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Withdrawal error:', err);
    res.status(500).json({ error: 'Withdrawal failed' });
  } finally {
    client.release();
  }
});

app.get('/api/withdraw/history', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, amount, method, status, created_at, processed_at FROM withdrawals WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.userId]
    );

    res.json({ success: true, withdrawals: result.rows });

  } catch (err) {
    console.error('History error:', err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

const adminAuth = (req, res, next) => {
  const { username, password } = req.headers;
  
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const todayRevenue = await pool.query(
      'SELECT * FROM daily_revenue WHERE date = CURRENT_DATE'
    );

    const totalUsers = await pool.query(
      'SELECT COUNT(*) as count FROM users'
    );

    const activeToday = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as count FROM ad_views WHERE DATE(created_at) = CURRENT_DATE'
    );

    const pendingWithdrawals = await pool.query(
      "SELECT SUM(amount) as total, COUNT(*) as count FROM withdrawals WHERE status = 'pending'"
    );

    const totalRevenue = await pool.query(
      'SELECT SUM(revenue) as revenue, SUM(paid_out) as paid_out, SUM(profit) as profit FROM daily_revenue'
    );

    const today = todayRevenue.rows[0] || { ad_views: 0, revenue: 0, paid_out: 0, profit: 0, active_users: 0 };

    res.json({
      success: true,
      today: {
        ad_views: today.ad_views || 0,
        revenue: parseFloat(today.revenue) || 0,
        paid_out: parseFloat(today.paid_out) || 0,
        profit: parseFloat(today.profit) || 0,
        active_users: today.active_users || 0
      },
      totalUsers: parseInt(totalUsers.rows[0].count),
      activeToday: parseInt(activeToday.rows[0].count),
      pendingWithdrawals: {
        amount: parseFloat(pendingWithdrawals.rows[0].total) || 0,
        count: parseInt(pendingWithdrawals.rows[0].count)
      },
      allTime: {
        revenue: parseFloat(totalRevenue.rows[0].revenue) || 0,
        paidOut: parseFloat(totalRevenue.rows[0].paid_out) || 0,
        profit: parseFloat(totalRevenue.rows[0].profit) || 0
      }
    });

  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT w.*, u.username, u.email 
       FROM withdrawals w 
       JOIN users u ON w.user_id = u.id 
       WHERE w.status = 'pending' 
       ORDER BY w.created_at DESC`
    );

    res.json({ success: true, withdrawals: result.rows });

  } catch (err) {
    console.error('Withdrawals error:', err);
    res.status(500).json({ error: 'Failed to fetch withdrawals' });
  }
});

app.post('/api/admin/withdrawals/:id/process', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { status, transactionId, notes } = req.body;

  try {
    await pool.query(
      'UPDATE withdrawals SET status = $1, transaction_id = $2, notes = $3, processed_at = NOW() WHERE id = $4',
      [status, transactionId, notes, id]
    );

    res.json({ success: true, message: 'Withdrawal updated' });

  } catch (err) {
    console.error('Process withdrawal error:', err);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date(), database: 'postgresql' });
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   EarnView Platform (PostgreSQL)       ║
  ║   Port: ${PORT}                           ║
  ║   Daily Limit: 500 ads                 ║
  ║   Max Earning: $25/day per user        ║
  ╚════════════════════════════════════════╝
  
  📊 Admin Panel: http://localhost:${PORT}/admin.html
  👤 User Dashboard: http://localhost:${PORT}/dashboard.html
  🔐 API Endpoints: http://localhost:${PORT}/api
  🐘 Database: PostgreSQL
  🐳 Running in Docker
  `);
});
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  balance DECIMAL(10,2) DEFAULT 0.00,
  total_earned DECIMAL(10,2) DEFAULT 0.00,
  ads_watched_today INT DEFAULT 0,
  last_ad_date DATE,
  referral_code VARCHAR(10) UNIQUE,
  referred_by INT REFERENCES users(id) ON DELETE SET NULL,
  paypal_email VARCHAR(100),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_referral_code ON users(referral_code);

CREATE TABLE IF NOT EXISTS ad_views (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ad_type VARCHAR(50) DEFAULT 'video',
  earning DECIMAL(10,2) NOT NULL,
  revenue DECIMAL(10,2) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ad_views_user_id ON ad_views(user_id);
CREATE INDEX idx_ad_views_created_at ON ad_views(created_at);

CREATE TABLE IF NOT EXISTS withdrawals (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount DECIMAL(10,2) NOT NULL,
  method VARCHAR(20) DEFAULT 'paypal',
  paypal_email VARCHAR(100),
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  transaction_id VARCHAR(100),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  processed_at TIMESTAMP
);

CREATE INDEX idx_withdrawals_user_id ON withdrawals(user_id);
CREATE INDEX idx_withdrawals_status ON withdrawals(status);

CREATE TABLE IF NOT EXISTS daily_revenue (
  date DATE PRIMARY KEY,
  ad_views INT DEFAULT 0,
  revenue DECIMAL(10,2) DEFAULT 0.00,
  paid_out DECIMAL(10,2) DEFAULT 0.00,
  profit DECIMAL(10,2) DEFAULT 0.00,
  active_users INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS referral_earnings (
  id SERIAL PRIMARY KEY,
  referrer_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  referred_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  earning DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO earnview;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO earnview;
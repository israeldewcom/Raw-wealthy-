-- Create database
CREATE DATABASE IF NOT EXISTS raw_wealthy;
USE raw_wealthy;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    password VARCHAR(255) NOT NULL,
    referral_code VARCHAR(10) UNIQUE,
    referred_by VARCHAR(10),
    risk_tolerance ENUM('low', 'medium', 'high') DEFAULT 'medium',
    investment_strategy ENUM('conservative', 'balanced', 'aggressive') DEFAULT 'balanced',
    balance DECIMAL(15,2) DEFAULT 0.00,
    total_earnings DECIMAL(15,2) DEFAULT 0.00,
    referral_earnings DECIMAL(15,2) DEFAULT 0.00,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    kyc_verified BOOLEAN DEFAULT FALSE,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Investment plans table
CREATE TABLE investment_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    min_amount DECIMAL(15,2) NOT NULL,
    max_amount DECIMAL(15,2),
    daily_interest DECIMAL(5,2) NOT NULL,
    total_interest DECIMAL(5,2) NOT NULL,
    duration INT NOT NULL,
    risk_level ENUM('low', 'medium', 'high') DEFAULT 'medium',
    is_popular BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Investments table
CREATE TABLE investments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    plan_id INT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    daily_earnings DECIMAL(15,2) DEFAULT 0.00,
    total_earnings DECIMAL(15,2) DEFAULT 0.00,
    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_date TIMESTAMP NULL,
    status ENUM('pending', 'active', 'completed', 'cancelled') DEFAULT 'pending',
    auto_renew BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES investment_plans(id) ON DELETE CASCADE
);

-- Deposits table
CREATE TABLE deposits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    payment_method ENUM('bank_transfer', 'crypto', 'paypal', 'card') NOT NULL,
    transaction_hash VARCHAR(255),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Withdrawals table
CREATE TABLE withdrawals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    fee DECIMAL(15,2) DEFAULT 0.00,
    net_amount DECIMAL(15,2) NOT NULL,
    payment_method ENUM('bank_transfer', 'crypto', 'paypal') NOT NULL,
    bank_name VARCHAR(255),
    account_name VARCHAR(255),
    account_number VARCHAR(255),
    wallet_address VARCHAR(255),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Referrals table
CREATE TABLE referrals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    referrer_id INT NOT NULL,
    referred_id INT NOT NULL,
    earnings DECIMAL(15,2) DEFAULT 0.00,
    status ENUM('pending', 'approved') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referred_id) REFERENCES users(id) ON DELETE CASCADE
);

-- KYC verifications table
CREATE TABLE kyc_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    id_type ENUM('national_id', 'passport', 'driver_license') NOT NULL,
    id_number VARCHAR(255) NOT NULL,
    id_front_image VARCHAR(255),
    id_back_image VARCHAR(255),
    selfie_with_id_image VARCHAR(255),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Support tickets table
CREATE TABLE support_tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    subject VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status ENUM('open', 'in_progress', 'closed') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Transactions table
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('deposit', 'withdrawal', 'investment', 'earning', 'referral') NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert sample investment plans
INSERT INTO investment_plans (name, description, min_amount, max_amount, daily_interest, total_interest, duration, risk_level, is_popular) VALUES
('Starter Plan', 'Perfect for beginners with low risk tolerance', 3500.00, 50000.00, 3.5, 105.0, 30, 'low', TRUE),
('Silver Plan', 'Balanced risk with moderate returns', 10000.00, 200000.00, 5.0, 150.0, 30, 'medium', TRUE),
('Gold Plan', 'High returns for experienced investors', 50000.00, 1000000.00, 7.5, 225.0, 30, 'high', TRUE),
('Platinum Plan', 'Maximum returns with premium features', 100000.00, NULL, 10.0, 300.0, 30, 'high', FALSE),
('Diamond Plan', 'Exclusive high-yield investment', 500000.00, NULL, 12.5, 375.0, 30, 'high', FALSE);

-- Create admin user (password: admin123)
INSERT INTO users (full_name, email, phone, password, role, balance, referral_code) VALUES 
('Admin User', 'admin@rawwealthy.com', '+2348000000000', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', 0.00, 'ADMIN001');

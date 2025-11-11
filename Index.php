<?php
/* 
 * Raw Wealthy Investment Platform - Enterprise Production Edition v12.0
 * FULLY INTEGRATED WITH FRONTEND - COMPLETE API COMPATIBILITY
 * Advanced Financial Platform with Real-time Processing
 * SECURE, SCALABLE, PRODUCTION-READY WITH FULL FRONTEND INTEGRATION
 */

// Enhanced error reporting for production
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// CORS headers for frontend integration
$allowed_origins = [
    'http://localhost:3000', 
    'http://127.0.0.1:3000', 
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'https://rawwealthy.com',
    'https://www.rawwealthy.com',
    'https://app.rawwealthy.com',
    'https://raw-wealthy-yibn.onrender.com'
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: *");
}
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-API-Key, X-CSRF-Token");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Max-Age: 86400");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict',
    'gc_maxlifetime' => 86400
]);

// Environment-based configuration
define('APP_NAME', 'Raw Wealthy Investment Platform');
define('APP_VERSION', '12.0.0');
define('BASE_URL', 'https://raw-wealthy-yibn.onrender.com/');
define('API_BASE', '/api/');
define('UPLOAD_PATH', __DIR__ . '/uploads/');
define('MAX_FILE_SIZE', 50 * 1024 * 1024);
define('JWT_SECRET', getenv('JWT_SECRET') ?: 'raw-wealthy-production-secure-key-2024-change-in-production');
define('JWT_EXPIRY', 86400 * 30);
define('REFERRAL_BONUS_RATE', 0.15);
define('WITHDRAWAL_FEE_RATE', 0.05);
define('MIN_DEPOSIT', 500);
define('MIN_WITHDRAWAL', 1000);
define('MAX_WITHDRAWAL', 1000000);
define('MIN_INVESTMENT', 3500);
define('DAILY_INTEREST_CALCULATION_HOUR', 9);
define('CSRF_SECRET', getenv('CSRF_SECRET') ?: 'csrf-secure-key-2024-change-in-production');

// Create directories if they don't exist
$directories = ['logs', 'uploads', 'uploads/proofs', 'uploads/kyc', 'uploads/avatars', 'cache', 'backups'];
foreach ($directories as $dir) {
    if (!is_dir(__DIR__ . '/' . $dir)) {
        mkdir(__DIR__ . '/' . $dir, 0755, true);
    }
}

class Database {
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn;
    private $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
        PDO::ATTR_PERSISTENT => true
    ];

    public function __construct() {
        $this->host = getenv('DB_HOST') ?: 'localhost';
        $this->db_name = getenv('DB_NAME') ?: 'raw_wealthy_enterprise';
        $this->username = getenv('DB_USER') ?: 'root';
        $this->password = getenv('DB_PASS') ?: '';
    }

    public function getConnection() {
        if ($this->conn === null) {
            try {
                $dsn = "mysql:host={$this->host};dbname={$this->db_name};charset=utf8mb4";
                $this->conn = new PDO($dsn, $this->username, $this->password, $this->options);
                
                // Test connection
                $this->conn->query("SELECT 1");
            } catch(PDOException $e) {
                error_log("Database connection error: " . $e->getMessage());
                
                // Create database if it doesn't exist
                if ($e->getCode() === 1049) {
                    $this->createDatabase();
                } else {
                    throw new Exception("Database connection failed. Please try again later.");
                }
            }
        }
        return $this->conn;
    }

    private function createDatabase() {
        try {
            $temp_dsn = "mysql:host={$this->host};charset=utf8mb4";
            $temp_conn = new PDO($temp_dsn, $this->username, $this->password);
            $temp_conn->exec("CREATE DATABASE IF NOT EXISTS {$this->db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $temp_conn = null;
            
            // Reconnect with database
            $dsn = "mysql:host={$this->host};dbname={$this->db_name};charset=utf8mb4";
            $this->conn = new PDO($dsn, $this->username, $this->password, $this->options);
            
            // Initialize tables
            $this->initializeDatabase();
            
        } catch (Exception $e) {
            throw new Exception("Failed to create database: " . $e->getMessage());
        }
    }

    public function initializeDatabase() {
        try {
            $sql = [
                // Users table
                "CREATE TABLE IF NOT EXISTS users (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    full_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    phone VARCHAR(50),
                    password_hash VARCHAR(255) NOT NULL,
                    balance DECIMAL(15,2) DEFAULT 100.00,
                    total_invested DECIMAL(15,2) DEFAULT 0.00,
                    total_earnings DECIMAL(15,2) DEFAULT 0.00,
                    referral_earnings DECIMAL(15,2) DEFAULT 0.00,
                    referral_code VARCHAR(20) UNIQUE,
                    referred_by VARCHAR(20),
                    role ENUM('user','admin','super_admin') DEFAULT 'user',
                    kyc_verified BOOLEAN DEFAULT FALSE,
                    kyc_data JSON,
                    status ENUM('active','suspended','pending') DEFAULT 'active',
                    two_factor_enabled BOOLEAN DEFAULT FALSE,
                    two_factor_secret VARCHAR(100),
                    risk_tolerance ENUM('low','medium','high') DEFAULT 'medium',
                    investment_strategy VARCHAR(100),
                    email_verified BOOLEAN DEFAULT FALSE,
                    avatar VARCHAR(255),
                    last_login TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_email (email),
                    INDEX idx_referral_code (referral_code),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Investment plans table
                "CREATE TABLE IF NOT EXISTS investment_plans (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    min_amount DECIMAL(15,2) NOT NULL,
                    max_amount DECIMAL(15,2),
                    daily_interest DECIMAL(5,2) NOT NULL,
                    total_interest DECIMAL(5,2) NOT NULL,
                    duration INT NOT NULL,
                    risk_level ENUM('low','medium','high') DEFAULT 'medium',
                    status ENUM('active','inactive') DEFAULT 'active',
                    features TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_status (status),
                    INDEX idx_risk_level (risk_level)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Investments table
                "CREATE TABLE IF NOT EXISTS investments (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    plan_id INT NOT NULL,
                    amount DECIMAL(15,2) NOT NULL,
                    daily_interest DECIMAL(5,2) NOT NULL,
                    total_interest DECIMAL(5,2) NOT NULL,
                    duration INT NOT NULL,
                    expected_earnings DECIMAL(15,2) NOT NULL,
                    earned_interest DECIMAL(15,2) DEFAULT 0.00,
                    auto_renew BOOLEAN DEFAULT FALSE,
                    risk_level ENUM('low','medium','high') DEFAULT 'medium',
                    proof_image VARCHAR(255),
                    status ENUM('pending','active','completed','cancelled') DEFAULT 'pending',
                    start_date TIMESTAMP NULL,
                    end_date TIMESTAMP NULL,
                    last_interest_calculation TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (plan_id) REFERENCES investment_plans(id) ON DELETE CASCADE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status),
                    INDEX idx_start_date (start_date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Transactions table
                "CREATE TABLE IF NOT EXISTS transactions (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    type ENUM('deposit','withdrawal','investment','interest','referral_bonus','transfer') NOT NULL,
                    amount DECIMAL(15,2) NOT NULL,
                    fee DECIMAL(15,2) DEFAULT 0.00,
                    net_amount DECIMAL(15,2) NOT NULL,
                    description TEXT,
                    status ENUM('pending','completed','failed','cancelled') DEFAULT 'pending',
                    reference VARCHAR(100) UNIQUE,
                    proof_image VARCHAR(255),
                    metadata JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_type (type),
                    INDEX idx_status (status),
                    INDEX idx_reference (reference)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Deposits table
                "CREATE TABLE IF NOT EXISTS deposits (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    amount DECIMAL(15,2) NOT NULL,
                    payment_method ENUM('bank_transfer','crypto','paypal','card') NOT NULL,
                    transaction_hash VARCHAR(255),
                    proof_image VARCHAR(255),
                    status ENUM('pending','approved','rejected') DEFAULT 'pending',
                    admin_notes TEXT,
                    reference VARCHAR(100) UNIQUE,
                    processed_by INT NULL,
                    processed_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Withdrawal requests table
                "CREATE TABLE IF NOT EXISTS withdrawal_requests (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    amount DECIMAL(15,2) NOT NULL,
                    fee DECIMAL(15,2) DEFAULT 0.00,
                    net_amount DECIMAL(15,2) NOT NULL,
                    payment_method ENUM('bank_transfer','crypto','paypal') NOT NULL,
                    bank_name VARCHAR(255),
                    account_number VARCHAR(50),
                    account_name VARCHAR(255),
                    wallet_address VARCHAR(255),
                    paypal_email VARCHAR(255),
                    status ENUM('pending','approved','rejected','processed') DEFAULT 'pending',
                    admin_notes TEXT,
                    user_notes TEXT,
                    reference VARCHAR(100) UNIQUE,
                    processed_by INT NULL,
                    processed_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Referral earnings table
                "CREATE TABLE IF NOT EXISTS referral_earnings (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    referrer_id INT NOT NULL,
                    referred_user_id INT NOT NULL,
                    amount DECIMAL(15,2) NOT NULL,
                    type ENUM('signup_bonus','investment_commission') DEFAULT 'signup_bonus',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (referred_user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_referrer_id (referrer_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Notifications table
                "CREATE TABLE IF NOT EXISTS notifications (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    type ENUM('info','success','warning','error') DEFAULT 'info',
                    is_read BOOLEAN DEFAULT FALSE,
                    action_url VARCHAR(500),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_is_read (is_read)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Audit logs table
                "CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NULL,
                    action VARCHAR(100) NOT NULL,
                    description TEXT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    metadata JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_action (action),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // KYC submissions table
                "CREATE TABLE IF NOT EXISTS kyc_submissions (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    document_type ENUM('id_card','passport','drivers_license','utility_bill') NOT NULL,
                    document_number VARCHAR(100),
                    front_image VARCHAR(255) NOT NULL,
                    back_image VARCHAR(255),
                    selfie_image VARCHAR(255),
                    status ENUM('pending','approved','rejected') DEFAULT 'pending',
                    admin_notes TEXT,
                    verified_by INT NULL,
                    verified_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL,
                    UNIQUE KEY unique_user_document (user_id, document_type),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Support tickets table
                "CREATE TABLE IF NOT EXISTS support_tickets (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    subject VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    status ENUM('open','in_progress','resolved','closed') DEFAULT 'open',
                    priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
                    category ENUM('general','technical','billing','investment','withdrawal','other') DEFAULT 'general',
                    admin_notes TEXT,
                    assigned_to INT NULL,
                    resolved_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status),
                    INDEX idx_category (category)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

                // Two-factor authentication table
                "CREATE TABLE IF NOT EXISTS two_factor_auth (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    secret VARCHAR(100) NOT NULL,
                    backup_codes TEXT,
                    is_active BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE KEY unique_user_id (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
            ];

            foreach ($sql as $query) {
                $this->conn->exec($query);
            }

            // Seed default data
            $this->seedDefaultData();

            error_log("Database initialized successfully");

        } catch (Exception $e) {
            error_log("Database initialization error: " . $e->getMessage());
            throw new Exception("Database setup failed: " . $e->getMessage());
        }
    }

    private function seedDefaultData() {
        try {
            // Check if plans already exist
            $stmt = $this->conn->query("SELECT COUNT(*) as count FROM investment_plans");
            $result = $stmt->fetch();
            
            if ($result['count'] == 0) {
                $plans = [
                    [
                        'name' => 'Starter Plan',
                        'description' => 'Perfect for beginners with low risk tolerance',
                        'min_amount' => 3500,
                        'max_amount' => 50000,
                        'daily_interest' => 2.5,
                        'total_interest' => 45,
                        'duration' => 18,
                        'risk_level' => 'low',
                        'features' => 'Secure Returns,Low Risk,Stable Growth,Weekly Payouts'
                    ],
                    [
                        'name' => 'Growth Plan',
                        'description' => 'Balanced growth with medium risk for steady returns',
                        'min_amount' => 50000,
                        'max_amount' => 500000,
                        'daily_interest' => 3.8,
                        'total_interest' => 95,
                        'duration' => 25,
                        'risk_level' => 'medium',
                        'features' => 'Balanced Growth,Medium Risk,Diversified Portfolio,Bi-Weekly Payouts'
                    ],
                    [
                        'name' => 'Premium Plan',
                        'description' => 'High returns for experienced investors with high risk tolerance',
                        'min_amount' => 500000,
                        'max_amount' => 5000000,
                        'daily_interest' => 5.2,
                        'total_interest' => 182,
                        'duration' => 35,
                        'risk_level' => 'high',
                        'features' => 'High Returns,Aggressive Growth,Expert Managed,Monthly Payouts'
                    ],
                    [
                        'name' => 'Elite Plan',
                        'description' => 'Maximum returns for premium investors with exclusive benefits',
                        'min_amount' => 1000000,
                        'max_amount' => 10000000,
                        'daily_interest' => 7.5,
                        'total_interest' => 350,
                        'duration' => 47,
                        'risk_level' => 'high',
                        'features' => 'Maximum Returns,Premium Support,Portfolio Management,Custom Strategies'
                    ]
                ];

                $stmt = $this->conn->prepare("
                    INSERT INTO investment_plans 
                    (name, description, min_amount, max_amount, daily_interest, total_interest, duration, risk_level, features) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");

                foreach ($plans as $plan) {
                    $stmt->execute([
                        $plan['name'],
                        $plan['description'],
                        $plan['min_amount'],
                        $plan['max_amount'],
                        $plan['daily_interest'],
                        $plan['total_interest'],
                        $plan['duration'],
                        $plan['risk_level'],
                        $plan['features']
                    ]);
                }

                // Create default admin user
                $admin_email = 'admin@rawwealthy.com';
                $admin_check = $this->conn->prepare("SELECT id FROM users WHERE email = ?");
                $admin_check->execute([$admin_email]);
                
                if (!$admin_check->fetch()) {
                    $admin_stmt = $this->conn->prepare("
                        INSERT INTO users 
                        (full_name, email, password_hash, role, email_verified, kyc_verified, referral_code, balance) 
                        VALUES (?, ?, ?, 'super_admin', TRUE, TRUE, ?, 100000.00)
                    ");
                    $admin_stmt->execute([
                        'System Administrator',
                        $admin_email,
                        password_hash('Admin123!', PASSWORD_BCRYPT),
                        'ADMIN' . strtoupper(uniqid())
                    ]);
                }

                error_log("Default data seeded successfully");
            }
        } catch (Exception $e) {
            error_log("Default data seeding error: " . $e->getMessage());
        }
    }

    public function beginTransaction() {
        return $this->conn->beginTransaction();
    }

    public function commit() {
        return $this->conn->commit();
    }

    public function rollBack() {
        return $this->conn->rollBack();
    }

    public function closeConnection() {
        $this->conn = null;
    }
}

class Security {
    public static function generateToken($payload) {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $payload['iss'] = BASE_URL;
        $payload['iat'] = time();
        $payload['exp'] = time() + JWT_EXPIRY;
        
        $encoded_header = self::base64UrlEncode(json_encode($header));
        $encoded_payload = self::base64UrlEncode(json_encode($payload));
        
        $signature = hash_hmac('sha256', $encoded_header . '.' . $encoded_payload, JWT_SECRET, true);
        $encoded_signature = self::base64UrlEncode($signature);

        return $encoded_header . '.' . $encoded_payload . '.' . $encoded_signature;
    }

    public static function verifyToken($token) {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                error_log("JWT Error: Invalid parts count");
                return false;
            }

            list($encoded_header, $encoded_payload, $encoded_signature) = $parts;
            $signature = self::base64UrlDecode($encoded_signature);
            $expected_signature = hash_hmac('sha256', $encoded_header . '.' . $encoded_payload, JWT_SECRET, true);
            
            if (!hash_equals($expected_signature, $signature)) {
                error_log("JWT Error: Signature mismatch");
                return false;
            }

            $payload = json_decode(self::base64UrlDecode($encoded_payload), true);
            if ($payload['exp'] < time()) {
                error_log("JWT Error: Token expired");
                return false;
            }

            return $payload;
        } catch (Exception $e) {
            error_log("JWT Verification Error: " . $e->getMessage());
            return false;
        }
    }

    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }

    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function generateReferralCode() {
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $code = 'RW';
        for ($i = 0; $i < 6; $i++) {
            $code .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $code;
    }

    public static function generate2FASecret() {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < 32; $i++) {
            $secret .= $chars[rand(0, strlen($chars) - 1)];
        }
        return $secret;
    }

    public static function validateFile($file, $allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf']) {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload error: ' . $file['error']);
        }

        if ($file['size'] > MAX_FILE_SIZE) {
            throw new Exception('File size too large. Maximum: ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB');
        }

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        if (!in_array($mime_type, $allowed_types)) {
            throw new Exception('Invalid file type. Allowed: ' . implode(', ', $allowed_types));
        }

        return $mime_type;
    }

    public static function generateOTP($length = 6) {
        $otp = '';
        for ($i = 0; $i < $length; $i++) {
            $otp .= rand(0, 9);
        }
        return $otp;
    }

    public static function generateTransactionReference($prefix = 'TXN') {
        return $prefix . time() . rand(1000, 9999);
    }

    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time();
        
        // Clean up old tokens
        foreach ($_SESSION['csrf_tokens'] as $stored_token => $timestamp) {
            if (time() - $timestamp > 3600) { // 1 hour
                unset($_SESSION['csrf_tokens'][$stored_token]);
            }
        }
        
        return $token;
    }

    public static function verifyCSRFToken($token) {
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $timestamp = $_SESSION['csrf_tokens'][$token];
        unset($_SESSION['csrf_tokens'][$token]);
        
        // Token is valid for 1 hour
        return (time() - $timestamp) <= 3600;
    }

    public static function rateLimit($key, $limit = 10, $timeout = 60) {
        $cache_file = __DIR__ . "/cache/rate_limit_$key.json";
        $now = time();
        
        if (file_exists($cache_file)) {
            $data = json_decode(file_get_contents($cache_file), true);
            if ($data['timestamp'] > $now - $timeout) {
                if ($data['count'] >= $limit) {
                    throw new Exception('Rate limit exceeded. Please try again later.');
                }
                $data['count']++;
            } else {
                $data = ['count' => 1, 'timestamp' => $now];
            }
        } else {
            $data = ['count' => 1, 'timestamp' => $now];
        }
        
        file_put_contents($cache_file, json_encode($data));
        return true;
    }

    public static function validateAmount($amount, $min, $max) {
        if (!is_numeric($amount) || $amount <= 0) {
            throw new Exception('Invalid amount');
        }
        if ($amount < $min) {
            throw new Exception("Minimum amount is " . number_format($min, 2));
        }
        if ($amount > $max) {
            throw new Exception("Maximum amount is " . number_format($max, 2));
        }
        return floatval($amount);
    }

    public static function validatePassword($password) {
        if (strlen($password) < 8) {
            throw new Exception('Password must be at least 8 characters long');
        }
        if (!preg_match('/[A-Z]/', $password)) {
            throw new Exception('Password must contain at least one uppercase letter');
        }
        if (!preg_match('/[a-z]/', $password)) {
            throw new Exception('Password must contain at least one lowercase letter');
        }
        if (!preg_match('/[0-9]/', $password)) {
            throw new Exception('Password must contain at least one number');
        }
        return true;
    }
}

class Response {
    public static function json($data, $status = 200) {
        http_response_code($status);
        header('Content-Type: application/json');
        
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function success($data = [], $message = '') {
        self::json([
            'success' => true,
            'message' => $message,
            'data' => $data,
            'timestamp' => time()
        ]);
    }

    public static function error($message, $status = 400, $code = null) {
        error_log("API Error: $message (Status: $status)");
        self::json([
            'success' => false,
            'message' => $message,
            'code' => $code,
            'timestamp' => time()
        ], $status);
    }

    public static function validationError($errors) {
        self::json([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $errors,
            'timestamp' => time()
        ], 422);
    }

    public static function file($file_path, $filename = null) {
        if (!file_exists($file_path)) {
            self::error('File not found', 404);
        }

        $filename = $filename ?: basename($file_path);
        $file_size = filesize($file_path);
        $mime_type = mime_content_type($file_path);

        header('Content-Type: ' . $mime_type);
        header('Content-Disposition: inline; filename="' . $filename . '"');
        header('Content-Length: ' . $file_size);
        header('Cache-Control: private, max-age=86400');
        
        readfile($file_path);
        exit;
    }

    public static function csrfToken() {
        $token = Security::generateCSRFToken();
        self::success(['csrf_token' => $token]);
    }
}

class FileUploader {
    private $allowed_extensions = [
        'image' => ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        'document' => ['pdf', 'doc', 'docx', 'txt']
    ];

    public function upload($file, $type = 'general', $user_id = null) {
        try {
            $mime_type = Security::validateFile($file);
            
            $category = strpos($mime_type, 'image/') === 0 ? 'image' : 'document';
            
            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = $this->generateFilename($extension, $type, $user_id);
            $upload_path = UPLOAD_PATH . $type . '/';
            
            if (!is_dir($upload_path)) {
                mkdir($upload_path, 0755, true);
            }
            
            $full_path = $upload_path . $filename;
            
            if (!move_uploaded_file($file['tmp_name'], $full_path)) {
                throw new Exception('Failed to move uploaded file');
            }
            
            $public_url = BASE_URL . "api/files/{$type}/{$filename}";
            
            return [
                'filename' => $filename,
                'original_name' => $file['name'],
                'path' => $full_path,
                'url' => $public_url,
                'size' => $file['size'],
                'mime_type' => $mime_type,
                'uploaded_at' => time()
            ];
            
        } catch (Exception $e) {
            error_log("File upload error: " . $e->getMessage());
            throw $e;
        }
    }

    private function generateFilename($extension, $type, $user_id = null) {
        $timestamp = time();
        $random = bin2hex(random_bytes(8));
        $user_prefix = $user_id ? "user_{$user_id}_" : "";
        return "{$user_prefix}{$type}_{$timestamp}_{$random}.{$extension}";
    }

    public function delete($file_path) {
        if (file_exists($file_path) && is_file($file_path)) {
            return unlink($file_path);
        }
        return false;
    }
}

// ENHANCED MODELS WITH FULL FRONTEND INTEGRATION

class UserModel {
    private $conn;
    private $table = 'users';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $this->conn->beginTransaction();
        
        try {
            $query = "INSERT INTO {$this->table} SET 
                full_name=:full_name, 
                email=:email, 
                phone=:phone, 
                password_hash=:password_hash, 
                referral_code=:referral_code, 
                referred_by=:referred_by,
                risk_tolerance=:risk_tolerance, 
                investment_strategy=:investment_strategy,
                email_verified=:email_verified";

            $stmt = $this->conn->prepare($query);
            
            $stmt->bindValue(':full_name', $data['full_name']);
            $stmt->bindValue(':email', $data['email']);
            $stmt->bindValue(':phone', $data['phone']);
            $stmt->bindValue(':password_hash', $data['password_hash']);
            $stmt->bindValue(':referral_code', $data['referral_code']);
            $stmt->bindValue(':referred_by', $data['referred_by']);
            $stmt->bindValue(':risk_tolerance', $data['risk_tolerance'] ?? 'medium');
            $stmt->bindValue(':investment_strategy', $data['investment_strategy'] ?? 'balanced');
            $stmt->bindValue(':email_verified', $data['email_verified'] ?? false);

            if (!$stmt->execute()) {
                throw new Exception('Failed to create user');
            }

            $user_id = $this->conn->lastInsertId();
            
            // Process referral bonus if applicable
            if (!empty($data['referred_by'])) {
                $this->processReferralBonus($data['referred_by'], $user_id, $data['full_name']);
            }

            // Create welcome notification
            $this->createNotification(
                $user_id,
                "🎉 Welcome to Raw Wealthy!",
                "Hello {$data['full_name']}! Your account has been created successfully. Start your investment journey today!",
                'success'
            );

            // Log user creation
            $this->logAudit($user_id, 'user_registration', "New user registration: {$data['email']}");

            $this->conn->commit();
            return $user_id;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getByEmail($email) {
        $query = "SELECT * FROM {$this->table} WHERE email = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$email]);
        return $stmt->fetch();
    }

    public function getById($id) {
        $query = "SELECT id, full_name, email, phone, balance, total_invested, total_earnings, 
                         referral_earnings, referral_code, referred_by, role, kyc_verified, status,
                         two_factor_enabled, risk_tolerance, investment_strategy, 
                         email_verified, avatar, last_login, created_at 
                  FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    public function getByReferralCode($code) {
        $query = "SELECT id, full_name FROM {$this->table} WHERE referral_code = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$code]);
        return $stmt->fetch();
    }

    public function updateBalance($user_id, $amount) {
        $query = "UPDATE {$this->table} SET balance = balance + ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$amount, $user_id]);
    }

    public function updateProfile($user_id, $data) {
        $query = "UPDATE {$this->table} SET full_name=?, phone=?, risk_tolerance=?, investment_strategy=?, avatar=? WHERE id=?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([
            $data['full_name'],
            $data['phone'],
            $data['risk_tolerance'] ?? 'medium',
            $data['investment_strategy'] ?? 'balanced',
            $data['avatar'] ?? null,
            $user_id
        ]);
    }

    public function changePassword($user_id, $new_hash) {
        $query = "UPDATE {$this->table} SET password_hash = ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$new_hash, $user_id]);
    }

    public function enable2FA($user_id, $secret) {
        $query = "UPDATE {$this->table} SET two_factor_enabled = TRUE, two_factor_secret = ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$secret, $user_id]);
    }

    public function disable2FA($user_id) {
        $query = "UPDATE {$this->table} SET two_factor_enabled = FALSE, two_factor_secret = '' WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id]);
    }

    public function updateKYCStatus($user_id, $status, $kyc_data = null) {
        $query = "UPDATE {$this->table} SET kyc_verified = ?, kyc_data = ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$status, $kyc_data, $user_id]);
    }

    public function verifyEmail($user_id) {
        $query = "UPDATE {$this->table} SET email_verified = TRUE WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id]);
    }

    public function updateLastLogin($user_id) {
        $query = "UPDATE {$this->table} SET last_login = CURRENT_TIMESTAMP WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id]);
    }

    public function getUserStats($user_id) {
        $query = "SELECT 
            COUNT(*) as total_investments,
            COALESCE(SUM(amount), 0) as total_invested,
            COALESCE(SUM(expected_earnings), 0) as total_earnings,
            COALESCE(SUM(earned_interest), 0) as total_earned_interest
            FROM investments 
            WHERE user_id = ? AND status IN ('active', 'completed')";
        
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id]);
        return $stmt->fetch();
    }

    public function getReferralStats($user_id) {
        $query = "SELECT 
            COUNT(*) as total_referrals,
            COALESCE(SUM(amount), 0) as total_referral_earnings
            FROM referral_earnings 
            WHERE referrer_id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id]);
        return $stmt->fetch();
    }

    public function getAllUsers($page = 1, $per_page = 20, $filters = []) {
        $offset = ($page - 1) * $per_page;
        $where = [];
        $params = [];

        if (!empty($filters['status'])) {
            $where[] = "status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['search'])) {
            $where[] = "(full_name LIKE ? OR email LIKE ?)";
            $search_term = "%{$filters['search']}%";
            $params[] = $search_term;
            $params[] = $search_term;
        }

        $where_clause = $where ? "WHERE " . implode(" AND ", $where) : "";

        $query = "SELECT id, full_name, email, phone, balance, referral_code, role, 
                         kyc_verified, status, created_at 
                  FROM {$this->table} 
                  {$where_clause}
                  ORDER BY created_at DESC 
                  LIMIT ? OFFSET ?";
        
        $params[] = $per_page;
        $params[] = $offset;

        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function getTotalUsersCount($filters = []) {
        $where = [];
        $params = [];

        if (!empty($filters['status'])) {
            $where[] = "status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['search'])) {
            $where[] = "(full_name LIKE ? OR email LIKE ?)";
            $search_term = "%{$filters['search']}%";
            $params[] = $search_term;
            $params[] = $search_term;
        }

        $where_clause = $where ? "WHERE " . implode(" AND ", $where) : "";

        $query = "SELECT COUNT(*) as total FROM {$this->table} {$where_clause}";
        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        return $stmt->fetch()['total'];
    }

    private function processReferralBonus($referral_code, $new_user_id, $new_user_name) {
        $referrer = $this->getByReferralCode($referral_code);
        if ($referrer) {
            $bonus_amount = 50.00;
            $this->updateBalance($referrer['id'], $bonus_amount);
            
            // Log referral bonus
            $this->logReferralBonus($referrer['id'], $new_user_id, $bonus_amount);
            
            // Create notification
            $this->createNotification(
                $referrer['id'],
                "🎊 Referral Bonus!",
                "You've received a ₦50 bonus for referring $new_user_name!",
                'success'
            );

            // Update referral earnings
            $this->updateReferralEarnings($referrer['id'], $bonus_amount);
        }
    }

    private function logReferralBonus($referrer_id, $referred_id, $amount) {
        $query = "INSERT INTO referral_earnings SET referrer_id=?, referred_user_id=?, amount=?, type='signup_bonus'";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$referrer_id, $referred_id, $amount]);
    }

    private function updateReferralEarnings($user_id, $amount) {
        $query = "UPDATE users SET referral_earnings = referral_earnings + ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$amount, $user_id]);
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications SET user_id=?, title=?, message=?, type=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $title, $message, $type]);
    }

    private function logAudit($user_id, $action, $description) {
        $query = "INSERT INTO audit_logs SET user_id=?, action=?, description=?, ip_address=?, user_agent=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([
            $user_id,
            $action,
            $description,
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    }
}

// Investment Plan Model
class InvestmentPlanModel {
    private $conn;
    private $table = 'investment_plans';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function getAll() {
        $query = "SELECT *, 
                  (min_amount <= 5000 AND daily_interest >= 3.0) as is_popular,
                  CASE 
                    WHEN risk_level = 'low' THEN 'Secure Returns,Low Risk,Stable Growth,Weekly Payouts'
                    WHEN risk_level = 'medium' THEN 'Balanced Growth,Medium Risk,Diversified Portfolio,Bi-Weekly Payouts'
                    ELSE 'High Returns,Aggressive Growth,Expert Managed,Monthly Payouts'
                  END as features
                  FROM {$this->table} 
                  WHERE status = 'active' 
                  ORDER BY min_amount ASC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        $plans = $stmt->fetchAll();
        
        foreach ($plans as &$plan) {
            $plan['features'] = explode(',', $plan['features']);
        }
        
        return $plans;
    }

    public function getById($id) {
        $query = "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }
}

// Enhanced Investment Model with Interest Calculation
class InvestmentModel {
    private $conn;
    private $table = 'investments';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $this->conn->beginTransaction();
        
        try {
            $query = "INSERT INTO {$this->table} SET 
                user_id=:user_id, 
                plan_id=:plan_id, 
                amount=:amount, 
                daily_interest=:daily_interest, 
                total_interest=:total_interest, 
                duration=:duration,
                expected_earnings=:expected_earnings, 
                auto_renew=:auto_renew, 
                risk_level=:risk_level,
                proof_image=:proof_image,
                status=:status";

            $stmt = $this->conn->prepare($query);
            
            $expected_earnings = $data['amount'] * ($data['total_interest'] / 100);

            $stmt->bindValue(':user_id', $data['user_id']);
            $stmt->bindValue(':plan_id', $data['plan_id']);
            $stmt->bindValue(':amount', $data['amount']);
            $stmt->bindValue(':daily_interest', $data['daily_interest']);
            $stmt->bindValue(':total_interest', $data['total_interest']);
            $stmt->bindValue(':duration', $data['duration']);
            $stmt->bindValue(':expected_earnings', $expected_earnings);
            $stmt->bindValue(':auto_renew', $data['auto_renew'] ?? false);
            $stmt->bindValue(':risk_level', $data['risk_level']);
            $stmt->bindValue(':proof_image', $data['proof_image'] ?? '');
            $stmt->bindValue(':status', $data['status'] ?? 'pending');

            if (!$stmt->execute()) {
                throw new Exception('Failed to create investment');
            }

            $investment_id = $this->conn->lastInsertId();
            
            // Update user's total invested
            $this->updateUserInvestmentStats($data['user_id'], $data['amount']);
            
            // Create transaction record
            $this->createTransaction($data['user_id'], 'investment', -$data['amount'], "Investment in plan");
            
            // Create notification
            $this->createNotification(
                $data['user_id'],
                "📈 Investment Submitted",
                "Your investment of ₦" . number_format($data['amount'], 2) . " is under review.",
                'info'
            );

            $this->conn->commit();
            return $investment_id;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getUserInvestments($user_id, $page = 1, $per_page = 10) {
        $offset = ($page - 1) * $per_page;
        $query = "SELECT i.*, p.name as plan_name FROM {$this->table} i 
                  LEFT JOIN investment_plans p ON i.plan_id = p.id 
                  WHERE i.user_id = ? ORDER BY i.created_at DESC LIMIT ? OFFSET ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(1, $user_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $per_page, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getActiveInvestments($user_id = null) {
        $query = "SELECT i.*, p.name as plan_name FROM {$this->table} i 
                  LEFT JOIN investment_plans p ON i.plan_id = p.id 
                  WHERE i.status = 'active'";
        
        if ($user_id) {
            $query .= " AND i.user_id = ?";
        }
        
        $query .= " ORDER BY i.created_at DESC";
        
        $stmt = $this->conn->prepare($query);
        if ($user_id) {
            $stmt->execute([$user_id]);
        } else {
            $stmt->execute();
        }
        return $stmt->fetchAll();
    }

    public function getPendingInvestments() {
        $query = "SELECT i.*, u.full_name, u.email, p.name as plan_name 
                  FROM {$this->table} i
                  JOIN users u ON i.user_id = u.id
                  JOIN investment_plans p ON i.plan_id = p.id
                  WHERE i.status = 'pending' ORDER BY i.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function updateStatus($investment_id, $status, $admin_id = null) {
        $this->conn->beginTransaction();
        
        try {
            // Get investment details
            $investment = $this->getById($investment_id);
            if (!$investment) {
                throw new Exception('Investment not found');
            }

            $query = "UPDATE {$this->table} SET status = ? WHERE id = ?";
            $stmt = $this->conn->prepare($query);
            
            if (!$stmt->execute([$status, $investment_id])) {
                throw new Exception('Failed to update investment status');
            }

            // If approved, set start date and calculate end date
            if ($status === 'active') {
                $this->activateInvestment($investment_id, $investment['duration']);
                
                // Create notification
                $this->createNotification(
                    $investment['user_id'],
                    "✅ Investment Activated",
                    "Your investment of ₦" . number_format($investment['amount'], 2) . " has been approved and is now active.",
                    'success'
                );
            }

            // If rejected, refund the amount
            if ($status === 'cancelled') {
                $this->refundInvestment($investment_id, $investment['user_id'], $investment['amount']);
            }

            $this->conn->commit();
            return true;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getById($id) {
        $query = "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    // Calculate daily interest for active investments
    public function calculateDailyInterest() {
        try {
            $active_investments = $this->getActiveInvestments();
            $today = date('Y-m-d');
            $processed_count = 0;
            
            foreach ($active_investments as $investment) {
                // Skip if interest already calculated today
                if ($investment['last_interest_calculation'] && 
                    date('Y-m-d', strtotime($investment['last_interest_calculation'])) === $today) {
                    continue;
                }

                // Calculate daily interest
                $daily_interest = ($investment['amount'] * $investment['daily_interest']) / 100;
                
                // Update earned interest
                $this->updateEarnedInterest($investment['id'], $daily_interest);
                
                // Add to user balance
                $this->addInterestToBalance($investment['user_id'], $daily_interest);
                
                // Create transaction record
                $this->createTransaction(
                    $investment['user_id'], 
                    'interest', 
                    $daily_interest, 
                    "Daily interest from investment"
                );

                // Check if investment period completed
                $this->checkInvestmentCompletion($investment);
                
                $processed_count++;
            }
            
            return $processed_count;
        } catch (Exception $e) {
            error_log("Interest calculation error: " . $e->getMessage());
            return false;
        }
    }

    private function activateInvestment($investment_id, $duration) {
        $start_date = date('Y-m-d H:i:s');
        $end_date = date('Y-m-d H:i:s', strtotime("+$duration days"));
        
        $query = "UPDATE {$this->table} SET status='active', start_date=?, end_date=?, last_interest_calculation=? WHERE id=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$start_date, $end_date, $start_date, $investment_id]);
    }

    private function refundInvestment($investment_id, $user_id, $amount) {
        // Refund user balance
        $userModel = new UserModel($this->conn);
        $userModel->updateBalance($user_id, $amount);
        
        // Create transaction record
        $this->createTransaction($user_id, 'investment', $amount, "Investment refund");
        
        // Create notification
        $this->createNotification(
            $user_id,
            "💰 Investment Refunded",
            "Your investment of ₦" . number_format($amount, 2) . " has been refunded.",
            'info'
        );
    }

    private function updateEarnedInterest($investment_id, $interest) {
        $query = "UPDATE {$this->table} SET earned_interest = earned_interest + ?, last_interest_calculation = NOW() WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$interest, $investment_id]);
    }

    private function addInterestToBalance($user_id, $interest) {
        $userModel = new UserModel($this->conn);
        $userModel->updateBalance($user_id, $interest);
        
        // Update total earnings
        $query = "UPDATE users SET total_earnings = total_earnings + ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$interest, $user_id]);
    }

    private function checkInvestmentCompletion($investment) {
        if (strtotime($investment['end_date']) <= time()) {
            $this->completeInvestment($investment['id']);
        }
    }

    private function completeInvestment($investment_id) {
        $query = "UPDATE {$this->table} SET status='completed' WHERE id=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$investment_id]);
        
        // Get investment details for notification
        $investment = $this->getById($investment_id);
        $this->createNotification(
            $investment['user_id'],
            "🎉 Investment Completed",
            "Your investment has been completed. Total earnings: ₦" . number_format($investment['earned_interest'], 2),
            'success'
        );
    }

    private function updateUserInvestmentStats($user_id, $amount) {
        $query = "UPDATE users SET total_invested = total_invested + ? WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$amount, $user_id]);
    }

    private function createTransaction($user_id, $type, $amount, $description) {
        $reference = Security::generateTransactionReference();
        $net_amount = $type === 'withdrawal' ? $amount * (1 - WITHDRAWAL_FEE_RATE) : $amount;
        
        $query = "INSERT INTO transactions SET 
            user_id=?, type=?, amount=?, net_amount=?, description=?, reference=?, status='completed'";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $type, abs($amount), $net_amount, $description, $reference]);
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications SET user_id=?, title=?, message=?, type=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $title, $message, $type]);
    }
}

// Transaction Model
class TransactionModel {
    private $conn;
    private $table = 'transactions';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function getUserTransactions($user_id, $page = 1, $per_page = 20) {
        $offset = ($page - 1) * $per_page;
        $query = "SELECT * FROM {$this->table} 
                  WHERE user_id = ? 
                  ORDER BY created_at DESC 
                  LIMIT ? OFFSET ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(1, $user_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $per_page, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function create($data) {
        $query = "INSERT INTO {$this->table} SET 
            user_id=:user_id, 
            type=:type, 
            amount=:amount, 
            fee=:fee,
            net_amount=:net_amount,
            description=:description,
            reference=:reference,
            status=:status,
            metadata=:metadata";

        $stmt = $this->conn->prepare($query);
        
        $stmt->bindValue(':user_id', $data['user_id']);
        $stmt->bindValue(':type', $data['type']);
        $stmt->bindValue(':amount', $data['amount']);
        $stmt->bindValue(':fee', $data['fee'] ?? 0);
        $stmt->bindValue(':net_amount', $data['net_amount'] ?? $data['amount']);
        $stmt->bindValue(':description', $data['description'] ?? '');
        $stmt->bindValue(':reference', $data['reference'] ?? Security::generateTransactionReference());
        $stmt->bindValue(':status', $data['status'] ?? 'pending');
        $stmt->bindValue(':metadata', $data['metadata'] ? json_encode($data['metadata']) : null);

        return $stmt->execute();
    }

    public function updateStatusByReference($reference, $status) {
        $query = "UPDATE {$this->table} SET status = ? WHERE reference = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$status, $reference]);
    }
}

// Deposit Model
class DepositModel {
    private $conn;
    private $table = 'deposits';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $this->conn->beginTransaction();
        
        try {
            $query = "INSERT INTO {$this->table} SET 
                user_id=:user_id, 
                amount=:amount, 
                payment_method=:payment_method,
                transaction_hash=:transaction_hash,
                proof_image=:proof_image,
                reference=:reference";

            $stmt = $this->conn->prepare($query);
            
            $reference = Security::generateTransactionReference('DEP');

            $stmt->bindValue(':user_id', $data['user_id']);
            $stmt->bindValue(':amount', $data['amount']);
            $stmt->bindValue(':payment_method', $data['payment_method']);
            $stmt->bindValue(':transaction_hash', $data['transaction_hash'] ?? '');
            $stmt->bindValue(':proof_image', $data['proof_image'] ?? '');
            $stmt->bindValue(':reference', $reference);

            if (!$stmt->execute()) {
                throw new Exception('Failed to create deposit request');
            }

            $deposit_id = $this->conn->lastInsertId();

            // Create transaction record
            $transactionModel = new TransactionModel($this->conn);
            $transactionModel->create([
                'user_id' => $data['user_id'],
                'type' => 'deposit',
                'amount' => $data['amount'],
                'description' => 'Deposit request',
                'reference' => $reference,
                'status' => 'pending',
                'metadata' => ['deposit_id' => $deposit_id]
            ]);

            // Create notification
            $this->createNotification(
                $data['user_id'],
                "💰 Deposit Request",
                "Your deposit request of ₦" . number_format($data['amount'], 2) . " has been submitted and is under review.",
                'info'
            );

            $this->conn->commit();
            return $deposit_id;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getUserDeposits($user_id, $page = 1, $per_page = 10) {
        $offset = ($page - 1) * $per_page;
        $query = "SELECT * FROM {$this->table} 
                  WHERE user_id = ? 
                  ORDER BY created_at DESC 
                  LIMIT ? OFFSET ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(1, $user_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $per_page, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getPendingDeposits() {
        $query = "SELECT d.*, u.full_name, u.email 
                  FROM {$this->table} d
                  JOIN users u ON d.user_id = u.id
                  WHERE d.status = 'pending' 
                  ORDER BY d.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function updateStatus($deposit_id, $status, $admin_id, $admin_notes = '') {
        $this->conn->beginTransaction();
        
        try {
            // Get deposit details
            $deposit = $this->getById($deposit_id);
            if (!$deposit) {
                throw new Exception('Deposit not found');
            }

            $query = "UPDATE {$this->table} SET status=?, admin_notes=?, processed_by=?, processed_at=NOW() WHERE id=?";
            $stmt = $this->conn->prepare($query);
            
            if (!$stmt->execute([$status, $admin_notes, $admin_id, $deposit_id])) {
                throw new Exception('Failed to update deposit status');
            }

            // Update transaction status
            $transactionModel = new TransactionModel($this->conn);
            $transactionModel->updateStatusByReference($deposit['reference'], $status);

            // If approved, add to user balance
            if ($status === 'approved') {
                $userModel = new UserModel($this->conn);
                $userModel->updateBalance($deposit['user_id'], $deposit['amount']);
                
                // Create notification
                $this->createNotification(
                    $deposit['user_id'],
                    "✅ Deposit Approved",
                    "Your deposit of ₦" . number_format($deposit['amount'], 2) . " has been approved and added to your balance.",
                    'success'
                );
            }

            // If rejected, notify user
            if ($status === 'rejected') {
                $this->createNotification(
                    $deposit['user_id'],
                    "❌ Deposit Rejected",
                    "Your deposit of ₦" . number_format($deposit['amount'], 2) . " has been rejected. " . ($admin_notes ? "Reason: $admin_notes" : ""),
                    'error'
                );
            }

            $this->conn->commit();
            return true;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getById($id) {
        $query = "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications SET user_id=?, title=?, message=?, type=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $title, $message, $type]);
    }
}

// Withdrawal Model
class WithdrawalModel {
    private $conn;
    private $table = 'withdrawal_requests';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $this->conn->beginTransaction();
        
        try {
            $query = "INSERT INTO {$this->table} SET 
                user_id=:user_id, 
                amount=:amount, 
                fee=:fee,
                net_amount=:net_amount,
                payment_method=:payment_method,
                bank_name=:bank_name,
                account_number=:account_number,
                account_name=:account_name,
                wallet_address=:wallet_address,
                paypal_email=:paypal_email,
                user_notes=:user_notes,
                reference=:reference";

            $stmt = $this->conn->prepare($query);
            
            $fee = $data['amount'] * WITHDRAWAL_FEE_RATE;
            $net_amount = $data['amount'] - $fee;
            $reference = Security::generateTransactionReference('WDL');

            $stmt->bindValue(':user_id', $data['user_id']);
            $stmt->bindValue(':amount', $data['amount']);
            $stmt->bindValue(':fee', $fee);
            $stmt->bindValue(':net_amount', $net_amount);
            $stmt->bindValue(':payment_method', $data['payment_method']);
            $stmt->bindValue(':bank_name', $data['bank_name'] ?? '');
            $stmt->bindValue(':account_number', $data['account_number'] ?? '');
            $stmt->bindValue(':account_name', $data['account_name'] ?? '');
            $stmt->bindValue(':wallet_address', $data['wallet_address'] ?? '');
            $stmt->bindValue(':paypal_email', $data['paypal_email'] ?? '');
            $stmt->bindValue(':user_notes', $data['user_notes'] ?? '');
            $stmt->bindValue(':reference', $reference);

            if (!$stmt->execute()) {
                throw new Exception('Failed to create withdrawal request');
            }

            $withdrawal_id = $this->conn->lastInsertId();

            // Deduct amount from user balance
            $userModel = new UserModel($this->conn);
            $userModel->updateBalance($data['user_id'], -$data['amount']);

            // Create transaction record
            $transactionModel = new TransactionModel($this->conn);
            $transactionModel->create([
                'user_id' => $data['user_id'],
                'type' => 'withdrawal',
                'amount' => -$data['amount'],
                'fee' => $fee,
                'net_amount' => -$net_amount,
                'description' => 'Withdrawal request',
                'reference' => $reference,
                'status' => 'pending',
                'metadata' => ['withdrawal_id' => $withdrawal_id]
            ]);

            // Create notification
            $this->createNotification(
                $data['user_id'],
                "💳 Withdrawal Request",
                "Your withdrawal request of ₦" . number_format($data['amount'], 2) . " has been submitted and is under review.",
                'info'
            );

            $this->conn->commit();
            return $withdrawal_id;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getUserWithdrawals($user_id, $page = 1, $per_page = 10) {
        $offset = ($page - 1) * $per_page;
        $query = "SELECT * FROM {$this->table} 
                  WHERE user_id = ? 
                  ORDER BY created_at DESC 
                  LIMIT ? OFFSET ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(1, $user_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $per_page, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getPendingWithdrawals() {
        $query = "SELECT w.*, u.full_name, u.email 
                  FROM {$this->table} w
                  JOIN users u ON w.user_id = u.id
                  WHERE w.status = 'pending' 
                  ORDER BY w.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function updateStatus($withdrawal_id, $status, $admin_id, $admin_notes = '') {
        $this->conn->beginTransaction();
        
        try {
            // Get withdrawal details
            $withdrawal = $this->getById($withdrawal_id);
            if (!$withdrawal) {
                throw new Exception('Withdrawal not found');
            }

            $query = "UPDATE {$this->table} SET status=?, admin_notes=?, processed_by=?, processed_at=NOW() WHERE id=?";
            $stmt = $this->conn->prepare($query);
            
            if (!$stmt->execute([$status, $admin_notes, $admin_id, $withdrawal_id])) {
                throw new Exception('Failed to update withdrawal status');
            }

            // Update transaction status
            $transactionModel = new TransactionModel($this->conn);
            $transactionModel->updateStatusByReference($withdrawal['reference'], $status);

            // If rejected, refund the amount
            if ($status === 'rejected') {
                $userModel = new UserModel($this->conn);
                $userModel->updateBalance($withdrawal['user_id'], $withdrawal['amount']);
            }

            // Create notification
            $status_message = $status === 'approved' ? 'approved and will be processed shortly' : 'rejected';
            $this->createNotification(
                $withdrawal['user_id'],
                "💳 Withdrawal " . ucfirst($status),
                "Your withdrawal request of ₦" . number_format($withdrawal['amount'], 2) . " has been $status_message.",
                $status === 'approved' ? 'success' : 'error'
            );

            $this->conn->commit();
            return true;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getById($id) {
        $query = "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications SET user_id=?, title=?, message=?, type=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $title, $message, $type]);
    }
}

// KYC Model
class KYCModel {
    private $conn;
    private $table = 'kyc_submissions';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $query = "INSERT INTO {$this->table} SET 
            user_id=:user_id, 
            document_type=:document_type, 
            document_number=:document_number,
            front_image=:front_image,
            back_image=:back_image,
            selfie_image=:selfie_image";

        $stmt = $this->conn->prepare($query);
        
        $stmt->bindValue(':user_id', $data['user_id']);
        $stmt->bindValue(':document_type', $data['document_type']);
        $stmt->bindValue(':document_number', $data['document_number']);
        $stmt->bindValue(':front_image', $data['front_image']);
        $stmt->bindValue(':back_image', $data['back_image'] ?? '');
        $stmt->bindValue(':selfie_image', $data['selfie_image'] ?? '');

        return $stmt->execute();
    }

    public function getByUserId($user_id) {
        $query = "SELECT * FROM {$this->table} WHERE user_id = ? ORDER BY created_at DESC LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id]);
        return $stmt->fetch();
    }

    public function getPendingSubmissions() {
        $query = "SELECT k.*, u.full_name, u.email 
                  FROM {$this->table} k
                  JOIN users u ON k.user_id = u.id
                  WHERE k.status = 'pending' 
                  ORDER BY k.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function updateStatus($submission_id, $status, $admin_id, $admin_notes = '') {
        $this->conn->beginTransaction();
        
        try {
            $query = "UPDATE {$this->table} SET status=?, admin_notes=?, verified_by=?, verified_at=NOW() WHERE id=?";
            $stmt = $this->conn->prepare($query);
            
            if (!$stmt->execute([$status, $admin_notes, $admin_id, $submission_id])) {
                throw new Exception('Failed to update KYC status');
            }

            // Get submission details
            $submission = $this->getById($submission_id);
            
            // Update user KYC status
            $userModel = new UserModel($this->conn);
            $userModel->updateKYCStatus($submission['user_id'], $status === 'approved');

            // Create notification
            $status_message = $status === 'approved' ? 'approved' : 'rejected';
            $this->createNotification(
                $submission['user_id'],
                "🆔 KYC Verification " . ucfirst($status),
                "Your KYC verification has been $status_message." . ($admin_notes ? " Note: $admin_notes" : ""),
                $status === 'approved' ? 'success' : 'error'
            );

            $this->conn->commit();
            return true;

        } catch (Exception $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }

    public function getById($id) {
        $query = "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications SET user_id=?, title=?, message=?, type=?";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id, $title, $message, $type]);
    }
}

// Support Model
class SupportModel {
    private $conn;
    private $table = 'support_tickets';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($data) {
        $query = "INSERT INTO {$this->table} SET 
            user_id=:user_id, 
            subject=:subject, 
            message=:message,
            category=:category,
            priority=:priority";

        $stmt = $this->conn->prepare($query);
        
        $stmt->bindValue(':user_id', $data['user_id']);
        $stmt->bindValue(':subject', $data['subject']);
        $stmt->bindValue(':message', $data['message']);
        $stmt->bindValue(':category', $data['category'] ?? 'general');
        $stmt->bindValue(':priority', $data['priority'] ?? 'medium');

        return $stmt->execute();
    }

    public function getUserTickets($user_id, $page = 1, $per_page = 10) {
        $offset = ($page - 1) * $per_page;
        $query = "SELECT * FROM {$this->table} 
                  WHERE user_id = ? 
                  ORDER BY created_at DESC 
                  LIMIT ? OFFSET ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(1, $user_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $per_page, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getAllTickets($page = 1, $per_page = 20, $filters = []) {
        $offset = ($page - 1) * $per_page;
        $where = [];
        $params = [];

        if (!empty($filters['status'])) {
            $where[] = "status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['category'])) {
            $where[] = "category = ?";
            $params[] = $filters['category'];
        }

        $where_clause = $where ? "WHERE " . implode(" AND ", $where) : "";

        $query = "SELECT s.*, u.full_name, u.email 
                  FROM {$this->table} s
                  JOIN users u ON s.user_id = u.id
                  {$where_clause}
                  ORDER BY s.created_at DESC 
                  LIMIT ? OFFSET ?";
        
        $params[] = $per_page;
        $params[] = $offset;

        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function updateStatus($ticket_id, $status, $admin_notes = '') {
        $query = "UPDATE {$this->table} SET status=?, admin_notes=?, updated_at=NOW() WHERE id=?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$status, $admin_notes, $ticket_id]);
    }

    public function getById($id) {
        $query = "SELECT s.*, u.full_name, u.email 
                  FROM {$this->table} s
                  JOIN users u ON s.user_id = u.id
                  WHERE s.id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$id]);
        return $stmt->fetch();
    }
}

// Two-Factor Authentication Model
class TwoFactorModel {
    private $conn;
    private $table = 'two_factor_auth';

    public function __construct($db) {
        $this->conn = $db;
    }

    public function setup($user_id, $secret) {
        $query = "INSERT INTO {$this->table} SET user_id=?, secret=?, is_active=? 
                  ON DUPLICATE KEY UPDATE secret=?, is_active=?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id, $secret, false, $secret, false]);
    }

    public function activate($user_id) {
        $query = "UPDATE {$this->table} SET is_active = TRUE WHERE user_id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id]);
    }

    public function deactivate($user_id) {
        $query = "UPDATE {$this->table} SET is_active = FALSE WHERE user_id = ?";
        $stmt = $this->conn->prepare($query);
        return $stmt->execute([$user_id]);
    }

    public function getByUserId($user_id) {
        $query = "SELECT * FROM {$this->table} WHERE user_id = ? LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$user_id]);
        return $stmt->fetch();
    }

    public function verifyCode($user_id, $code) {
        $record = $this->getByUserId($user_id);
        if (!$record) {
            return false;
        }

        // In a real implementation, you would use a proper TOTP library
        // This is a simplified version for demonstration
        $current_code = $this->generateTOTP($record['secret']);
        return hash_equals($current_code, $code);
    }

    private function generateTOTP($secret) {
        // Simplified TOTP generation - in production use a proper library like:
        // https://github.com/robthree/twofactorauth
        $time = floor(time() / 30);
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $time), $secret);
        $offset = hexdec(substr($hash, -1)) & 0xF;
        $code = (
            ((hexdec(substr($hash, $offset * 2, 8)) & 0x7FFFFFFF) % 1000000)
        );
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
}

// ENHANCED CONTROLLERS WITH FULL FRONTEND INTEGRATION

class AuthController {
    private $userModel;
    private $twoFactorModel;

    public function __construct($db) {
        $this->userModel = new UserModel($db);
        $this->twoFactorModel = new TwoFactorModel($db);
    }

    public function register($data) {
        try {
            Security::rateLimit('register_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 5, 3600);
            
            $errors = [];
            if (empty($data['full_name'])) $errors['full_name'] = 'Full name is required';
            if (empty($data['email'])) $errors['email'] = 'Email is required';
            if (empty($data['phone'])) $errors['phone'] = 'Phone is required';
            if (empty($data['password'])) $errors['password'] = 'Password is required';
            
            if (!empty($errors)) {
                Response::validationError($errors);
            }

            // Validate password strength
            try {
                Security::validatePassword($data['password']);
            } catch (Exception $e) {
                Response::error($e->getMessage());
            }

            if (!Security::validateEmail($data['email'])) {
                Response::error('Invalid email format');
            }

            if ($this->userModel->getByEmail($data['email'])) {
                Response::error('Email already registered');
            }

            $referred_by = null;
            if (!empty($data['referral_code'])) {
                $referrer = $this->userModel->getByReferralCode($data['referral_code']);
                if (!$referrer) {
                    Response::error('Invalid referral code');
                }
                $referred_by = $data['referral_code'];
            }

            $user_data = [
                'full_name' => Security::sanitizeInput($data['full_name']),
                'email' => Security::sanitizeInput($data['email']),
                'phone' => Security::sanitizeInput($data['phone']),
                'password_hash' => Security::hashPassword($data['password']),
                'referral_code' => Security::generateReferralCode(),
                'referred_by' => $referred_by,
                'risk_tolerance' => $data['risk_tolerance'] ?? 'medium',
                'investment_strategy' => $data['investment_strategy'] ?? 'balanced',
                'email_verified' => false
            ];

            $user_id = $this->userModel->create($user_data);
            if (!$user_id) {
                Response::error('Registration failed');
            }

            $token = Security::generateToken([
                'user_id' => $user_id,
                'email' => $user_data['email'],
                'role' => 'user'
            ]);

            $user = $this->userModel->getById($user_id);

            Response::success([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'full_name' => $user['full_name'],
                    'email' => $user['email'],
                    'phone' => $user['phone'],
                    'balance' => $user['balance'],
                    'referral_code' => $user['referral_code'],
                    'role' => $user['role'],
                    'kyc_verified' => $user['kyc_verified'],
                    'risk_tolerance' => $user['risk_tolerance'],
                    'investment_strategy' => $user['investment_strategy'],
                    'two_factor_enabled' => $user['two_factor_enabled']
                ]
            ], 'Registration successful! Welcome to Raw Wealthy!');

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function login($data) {
        try {
            Security::rateLimit('login_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 5, 900);
            
            if (empty($data['email']) || empty($data['password'])) {
                Response::error('Email and password required');
            }

            $user = $this->userModel->getByEmail($data['email']);
            if (!$user || !Security::verifyPassword($data['password'], $user['password_hash'])) {
                Response::error('Invalid email or password');
            }

            if ($user['status'] === 'suspended') {
                Response::error('Account suspended. Please contact support.');
            }

            // Update last login
            $this->userModel->updateLastLogin($user['id']);

            // Check if 2FA is enabled
            $twoFactorRecord = $this->twoFactorModel->getByUserId($user['id']);
            $requires_2fa = $twoFactorRecord && $twoFactorRecord['is_active'];

            if ($requires_2fa && empty($data['two_factor_code'])) {
                $temp_token = Security::generateToken([
                    'user_id' => $user['id'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'requires_2fa' => true,
                    'exp' => time() + 600
                ]);

                Response::success([
                    'requires_2fa' => true,
                    'temp_token' => $temp_token
                ], '2FA verification required');
            }

            if ($requires_2fa && !empty($data['two_factor_code'])) {
                if (!$this->twoFactorModel->verifyCode($user['id'], $data['two_factor_code'])) {
                    Response::error('Invalid 2FA code');
                }
            }

            $token = Security::generateToken([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role']
            ]);

            Response::success([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'full_name' => $user['full_name'],
                    'email' => $user['email'],
                    'phone' => $user['phone'],
                    'role' => $user['role'],
                    'referral_code' => $user['referral_code'],
                    'balance' => $user['balance'],
                    'kyc_verified' => $user['kyc_verified'],
                    'risk_tolerance' => $user['risk_tolerance'],
                    'investment_strategy' => $user['investment_strategy'],
                    'two_factor_enabled' => $user['two_factor_enabled']
                ]
            ], 'Login successful');

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getProfile($user_id) {
        try {
            $user = $this->userModel->getById($user_id);
            if (!$user) {
                Response::error('User not found');
            }

            $user_stats = $this->userModel->getUserStats($user_id);
            $referral_stats = $this->userModel->getReferralStats($user_id);
            $investment_model = new InvestmentModel($this->userModel->getConnection());
            $active_investments = $investment_model->getActiveInvestments($user_id);

            $dashboard_stats = [
                'active_investments' => count($active_investments),
                'active_investment_value' => array_sum(array_column($active_investments, 'amount')),
                'total_earnings' => $user_stats['total_earnings'],
                'total_invested' => $user_stats['total_invested'],
                'total_referrals' => $referral_stats['total_referrals'],
                'referral_earnings' => $referral_stats['total_referral_earnings']
            ];

            Response::success([
                'user' => $user,
                'dashboard_stats' => $dashboard_stats
            ]);

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function updateProfile($user_id, $data, $files = []) {
        try {
            $update_data = [
                'full_name' => $data['full_name'],
                'phone' => $data['phone'],
                'risk_tolerance' => $data['risk_tolerance'] ?? 'medium',
                'investment_strategy' => $data['investment_strategy'] ?? 'balanced'
            ];

            if (!empty($files['avatar'])) {
                $uploader = new FileUploader();
                $avatar = $uploader->upload($files['avatar'], 'avatars', $user_id);
                $update_data['avatar'] = $avatar['filename'];
            }

            $result = $this->userModel->updateProfile($user_id, $update_data);
            if ($result) {
                Response::success(null, 'Profile updated successfully');
            } else {
                Response::error('Profile update failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function changePassword($user_id, $data) {
        try {
            $user = $this->userModel->getById($user_id);
            if (!Security::verifyPassword($data['current_password'], $user['password_hash'])) {
                Response::error('Current password is incorrect');
            }

            // Validate new password strength
            try {
                Security::validatePassword($data['new_password']);
            } catch (Exception $e) {
                Response::error($e->getMessage());
            }

            $new_hash = Security::hashPassword($data['new_password']);
            $result = $this->userModel->changePassword($user_id, $new_hash);
            if ($result) {
                Response::success(null, 'Password changed successfully');
            } else {
                Response::error('Password change failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class InvestmentController {
    private $investmentModel;
    private $planModel;
    private $userModel;

    public function __construct($db) {
        $this->investmentModel = new InvestmentModel($db);
        $this->planModel = new InvestmentPlanModel($db);
        $this->userModel = new UserModel($db);
    }

    public function getPlans() {
        try {
            $plans = $this->planModel->getAll();
            Response::success(['plans' => $plans]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function createInvestment($user_id, $data, $files = []) {
        try {
            Security::rateLimit('investment_' . $user_id, 10, 3600);
            
            if (empty($data['plan_id']) || empty($data['amount'])) {
                Response::error('Plan and amount are required');
            }

            $amount = Security::validateAmount($data['amount'], MIN_INVESTMENT, 10000000);

            $user = $this->userModel->getById($user_id);
            if ($user['balance'] < $amount) {
                Response::error('Insufficient balance');
            }

            $plan = $this->planModel->getById($data['plan_id']);
            if (!$plan) {
                Response::error('Invalid investment plan');
            }

            if ($amount < $plan['min_amount']) {
                Response::error('Minimum investment for this plan is ₦' . number_format($plan['min_amount'], 2));
            }

            if ($plan['max_amount'] && $amount > $plan['max_amount']) {
                Response::error('Maximum investment for this plan is ₦' . number_format($plan['max_amount'], 2));
            }

            $proof_image = '';
            if (!empty($files['proof_image'])) {
                $uploader = new FileUploader();
                $proof = $uploader->upload($files['proof_image'], 'proofs', $user_id);
                $proof_image = $proof['filename'];
            }

            $investment_data = [
                'user_id' => $user_id,
                'plan_id' => $data['plan_id'],
                'amount' => $amount,
                'daily_interest' => $plan['daily_interest'],
                'total_interest' => $plan['total_interest'],
                'duration' => $plan['duration'],
                'auto_renew' => $data['auto_renew'] ?? false,
                'risk_level' => $plan['risk_level'],
                'proof_image' => $proof_image,
                'status' => 'pending'
            ];

            $investment_id = $this->investmentModel->create($investment_data);
            if (!$investment_id) {
                Response::error('Investment creation failed');
            }

            Response::success([
                'investment_id' => $investment_id,
                'investment' => [
                    'id' => $investment_id,
                    'plan_id' => $data['plan_id'],
                    'amount' => $amount,
                    'status' => 'pending',
                    'created_at' => date('Y-m-d H:i:s')
                ]
            ], 'Investment created successfully and pending approval');

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getUserInvestments($user_id, $page = 1) {
        try {
            $investments = $this->investmentModel->getUserInvestments($user_id, $page);
            Response::success(['investments' => $investments]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getActiveInvestments($user_id = null) {
        try {
            $investments = $this->investmentModel->getActiveInvestments($user_id);
            Response::success(['investments' => $investments]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getPendingInvestments() {
        try {
            $investments = $this->investmentModel->getPendingInvestments();
            Response::success(['investments' => $investments]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function approveInvestment($investment_id, $admin_id) {
        try {
            $result = $this->investmentModel->updateStatus($investment_id, 'active', $admin_id);
            if ($result) {
                Response::success(null, 'Investment approved successfully');
            } else {
                Response::error('Investment approval failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function rejectInvestment($investment_id, $admin_id) {
        try {
            $result = $this->investmentModel->updateStatus($investment_id, 'cancelled', $admin_id);
            if ($result) {
                Response::success(null, 'Investment rejected and amount refunded');
            } else {
                Response::error('Investment rejection failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class TransactionController {
    private $transactionModel;

    public function __construct($db) {
        $this->transactionModel = new TransactionModel($db);
    }

    public function getUserTransactions($user_id, $page = 1) {
        try {
            $transactions = $this->transactionModel->getUserTransactions($user_id, $page);
            Response::success(['transactions' => $transactions]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class DepositController {
    private $depositModel;
    private $userModel;

    public function __construct($db) {
        $this->depositModel = new DepositModel($db);
        $this->userModel = new UserModel($db);
    }

    public function createDeposit($user_id, $data, $files = []) {
        try {
            Security::rateLimit('deposit_' . $user_id, 5, 3600);
            
            if (empty($data['amount']) || empty($data['payment_method'])) {
                Response::error('Amount and payment method are required');
            }

            $amount = Security::validateAmount($data['amount'], MIN_DEPOSIT, 10000000);

            $proof_image = '';
            if (!empty($files['proof_image'])) {
                $uploader = new FileUploader();
                $proof = $uploader->upload($files['proof_image'], 'proofs', $user_id);
                $proof_image = $proof['filename'];
            }

            $deposit_data = [
                'user_id' => $user_id,
                'amount' => $amount,
                'payment_method' => $data['payment_method'],
                'transaction_hash' => $data['transaction_hash'] ?? '',
                'proof_image' => $proof_image
            ];

            $deposit_id = $this->depositModel->create($deposit_data);
            if (!$deposit_id) {
                Response::error('Deposit request failed');
            }

            Response::success([
                'deposit_id' => $deposit_id,
                'amount' => $amount
            ], 'Deposit request submitted successfully');

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getUserDeposits($user_id, $page = 1) {
        try {
            $deposits = $this->depositModel->getUserDeposits($user_id, $page);
            Response::success(['deposits' => $deposits]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getPendingDeposits() {
        try {
            $deposits = $this->depositModel->getPendingDeposits();
            Response::success(['deposits' => $deposits]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function approveDeposit($deposit_id, $admin_id) {
        try {
            $result = $this->depositModel->updateStatus($deposit_id, 'approved', $admin_id);
            if ($result) {
                Response::success(null, 'Deposit approved successfully');
            } else {
                Response::error('Deposit approval failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function rejectDeposit($deposit_id, $admin_id, $data) {
        try {
            $admin_notes = $data['admin_notes'] ?? '';
            $result = $this->depositModel->updateStatus($deposit_id, 'rejected', $admin_id, $admin_notes);
            if ($result) {
                Response::success(null, 'Deposit rejected successfully');
            } else {
                Response::error('Deposit rejection failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class WithdrawalController {
    private $withdrawalModel;
    private $userModel;

    public function __construct($db) {
        $this->withdrawalModel = new WithdrawalModel($db);
        $this->userModel = new UserModel($db);
    }

    public function createWithdrawal($user_id, $data) {
        try {
            Security::rateLimit('withdrawal_' . $user_id, 5, 3600);
            
            if (empty($data['amount']) || empty($data['payment_method'])) {
                Response::error('Amount and payment method are required');
            }

            $amount = Security::validateAmount($data['amount'], MIN_WITHDRAWAL, MAX_WITHDRAWAL);

            $user = $this->userModel->getById($user_id);
            if ($user['balance'] < $amount) {
                Response::error('Insufficient balance');
            }

            $withdrawal_data = [
                'user_id' => $user_id,
                'amount' => $amount,
                'payment_method' => $data['payment_method'],
                'bank_name' => $data['bank_name'] ?? '',
                'account_number' => $data['account_number'] ?? '',
                'account_name' => $data['account_name'] ?? '',
                'wallet_address' => $data['wallet_address'] ?? '',
                'paypal_email' => $data['paypal_email'] ?? '',
                'user_notes' => $data['user_notes'] ?? ''
            ];

            $withdrawal_id = $this->withdrawalModel->create($withdrawal_data);
            if (!$withdrawal_id) {
                Response::error('Withdrawal request failed');
            }

            Response::success([
                'withdrawal_id' => $withdrawal_id,
                'amount' => $amount,
                'fee' => $amount * WITHDRAWAL_FEE_RATE,
                'net_amount' => $amount * (1 - WITHDRAWAL_FEE_RATE)
            ], 'Withdrawal request submitted successfully');

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getUserWithdrawals($user_id, $page = 1) {
        try {
            $withdrawals = $this->withdrawalModel->getUserWithdrawals($user_id, $page);
            Response::success(['withdrawals' => $withdrawals]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getPendingWithdrawals() {
        try {
            $withdrawals = $this->withdrawalModel->getPendingWithdrawals();
            Response::success(['withdrawals' => $withdrawals]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function approveWithdrawal($withdrawal_id, $admin_id) {
        try {
            $result = $this->withdrawalModel->updateStatus($withdrawal_id, 'approved', $admin_id);
            if ($result) {
                Response::success(null, 'Withdrawal approved successfully');
            } else {
                Response::error('Withdrawal approval failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function rejectWithdrawal($withdrawal_id, $admin_id, $data) {
        try {
            $admin_notes = $data['admin_notes'] ?? '';
            $result = $this->withdrawalModel->updateStatus($withdrawal_id, 'rejected', $admin_id, $admin_notes);
            if ($result) {
                Response::success(null, 'Withdrawal rejected successfully');
            } else {
                Response::error('Withdrawal rejection failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class ReferralController {
    private $userModel;

    public function __construct($db) {
        $this->userModel = new UserModel($db);
    }

    public function getReferralStats($user_id) {
        try {
            $stats = $this->userModel->getReferralStats($user_id);
            $user = $this->userModel->getById($user_id);
            
            $referral_link = BASE_URL . "?ref=" . $user['referral_code'];
            
            Response::success([
                'stats' => $stats,
                'referral_link' => $referral_link,
                'referral_code' => $user['referral_code']
            ]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class KYCController {
    private $kycModel;
    private $userModel;

    public function __construct($db) {
        $this->kycModel = new KYCModel($db);
        $this->userModel = new UserModel($db);
    }

    public function submitKYC($user_id, $data, $files = []) {
        try {
            if (empty($data['document_type']) || empty($data['document_number'])) {
                Response::error('Document type and number are required');
            }

            if (empty($files['front_image'])) {
                Response::error('Front image of document is required');
            }

            $uploader = new FileUploader();
            
            // Upload front image
            $front_image = $uploader->upload($files['front_image'], 'kyc', $user_id);
            
            // Upload back image if provided
            $back_image = '';
            if (!empty($files['back_image'])) {
                $back_image_data = $uploader->upload($files['back_image'], 'kyc', $user_id);
                $back_image = $back_image_data['filename'];
            }

            // Upload selfie if provided
            $selfie_image = '';
            if (!empty($files['selfie_image'])) {
                $selfie_image_data = $uploader->upload($files['selfie_image'], 'kyc', $user_id);
                $selfie_image = $selfie_image_data['filename'];
            }

            $kyc_data = [
                'user_id' => $user_id,
                'document_type' => $data['document_type'],
                'document_number' => $data['document_number'],
                'front_image' => $front_image['filename'],
                'back_image' => $back_image,
                'selfie_image' => $selfie_image
            ];

            $result = $this->kycModel->create($kyc_data);
            if ($result) {
                Response::success(null, 'KYC application submitted successfully');
            } else {
                Response::error('KYC submission failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getKYCStatus($user_id) {
        try {
            $submission = $this->kycModel->getByUserId($user_id);
            Response::success(['submission' => $submission]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getPendingSubmissions() {
        try {
            $submissions = $this->kycModel->getPendingSubmissions();
            Response::success(['submissions' => $submissions]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function approveKYC($submission_id, $admin_id) {
        try {
            $result = $this->kycModel->updateStatus($submission_id, 'approved', $admin_id);
            if ($result) {
                Response::success(null, 'KYC approved successfully');
            } else {
                Response::error('KYC approval failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function rejectKYC($submission_id, $admin_id, $data) {
        try {
            $admin_notes = $data['admin_notes'] ?? '';
            $result = $this->kycModel->updateStatus($submission_id, 'rejected', $admin_id, $admin_notes);
            if ($result) {
                Response::success(null, 'KYC rejected successfully');
            } else {
                Response::error('KYC rejection failed');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class SupportController {
    private $supportModel;

    public function __construct($db) {
        $this->supportModel = new SupportModel($db);
    }

    public function createTicket($user_id, $data) {
        try {
            if (empty($data['subject']) || empty($data['message'])) {
                Response::error('Subject and message are required');
            }

            $ticket_data = [
                'user_id' => $user_id,
                'subject' => $data['subject'],
                'message' => $data['message'],
                'category' => $data['category'] ?? 'general',
                'priority' => $data['priority'] ?? 'medium'
            ];

            $result = $this->supportModel->create($ticket_data);
            if ($result) {
                Response::success(null, 'Support ticket created successfully');
            } else {
                Response::error('Failed to create support ticket');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getUserTickets($user_id, $page = 1) {
        try {
            $tickets = $this->supportModel->getUserTickets($user_id, $page);
            Response::success(['tickets' => $tickets]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getAllTickets($page = 1, $filters = []) {
        try {
            $tickets = $this->supportModel->getAllTickets($page, 20, $filters);
            Response::success(['tickets' => $tickets]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function updateTicketStatus($ticket_id, $data) {
        try {
            $status = $data['status'];
            $admin_notes = $data['admin_notes'] ?? '';
            
            $result = $this->supportModel->updateStatus($ticket_id, $status, $admin_notes);
            if ($result) {
                Response::success(null, 'Ticket status updated successfully');
            } else {
                Response::error('Failed to update ticket status');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getTicket($ticket_id) {
        try {
            $ticket = $this->supportModel->getById($ticket_id);
            if (!$ticket) {
                Response::error('Ticket not found');
            }
            Response::success(['ticket' => $ticket]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class TwoFactorController {
    private $twoFactorModel;
    private $userModel;

    public function __construct($db) {
        $this->twoFactorModel = new TwoFactorModel($db);
        $this->userModel = new UserModel($db);
    }

    public function setup2FA($user_id) {
        try {
            $secret = Security::generate2FASecret();
            $result = $this->twoFactorModel->setup($user_id, $secret);
            
            if ($result) {
                Response::success([
                    'secret' => $secret,
                    'qr_code_url' => $this->generateQRCodeUrl($secret)
                ], '2FA setup initiated');
            } else {
                Response::error('Failed to setup 2FA');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function verify2FA($user_id, $data) {
        try {
            if (empty($data['code'])) {
                Response::error('2FA code is required');
            }

            $verified = $this->twoFactorModel->verifyCode($user_id, $data['code']);
            if ($verified) {
                $this->twoFactorModel->activate($user_id);
                $this->userModel->enable2FA($user_id, $this->twoFactorModel->getByUserId($user_id)['secret']);
                
                Response::success(null, '2FA activated successfully');
            } else {
                Response::error('Invalid 2FA code');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function disable2FA($user_id, $data) {
        try {
            if (empty($data['code'])) {
                Response::error('2FA code is required');
            }

            $verified = $this->twoFactorModel->verifyCode($user_id, $data['code']);
            if ($verified) {
                $this->twoFactorModel->deactivate($user_id);
                $this->userModel->disable2FA($user_id);
                
                Response::success(null, '2FA disabled successfully');
            } else {
                Response::error('Invalid 2FA code');
            }
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    private function generateQRCodeUrl($secret) {
        $issuer = 'Raw Wealthy';
        $account = 'User Account';
        return "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" . urlencode("otpauth://totp/{$issuer}:{$account}?secret={$secret}&issuer={$issuer}");
    }
}

class AdminController {
    private $userModel;
    private $investmentModel;
    private $depositModel;
    private $withdrawalModel;
    private $transactionModel;

    public function __construct($db) {
        $this->userModel = new UserModel($db);
        $this->investmentModel = new InvestmentModel($db);
        $this->depositModel = new DepositModel($db);
        $this->withdrawalModel = new WithdrawalModel($db);
        $this->transactionModel = new TransactionModel($db);
    }

    public function getDashboardStats() {
        try {
            $conn = $this->userModel->getConnection();
            
            // Total users
            $stmt = $conn->query("SELECT COUNT(*) as total_users FROM users");
            $total_users = $stmt->fetch()['total_users'];
            
            // Total investments
            $stmt = $conn->query("SELECT COUNT(*) as total_investments, COALESCE(SUM(amount), 0) as total_invested FROM investments WHERE status = 'active'");
            $investment_stats = $stmt->fetch();
            
            // Total deposits
            $stmt = $conn->query("SELECT COUNT(*) as total_deposits, COALESCE(SUM(amount), 0) as total_deposited FROM deposits WHERE status = 'approved'");
            $deposit_stats = $stmt->fetch();
            
            // Total withdrawals
            $stmt = $conn->query("SELECT COUNT(*) as total_withdrawals, COALESCE(SUM(amount), 0) as total_withdrawn FROM withdrawal_requests WHERE status = 'approved'");
            $withdrawal_stats = $stmt->fetch();
            
            // Pending actions
            $stmt = $conn->query("SELECT COUNT(*) as pending_investments FROM investments WHERE status = 'pending'");
            $pending_investments = $stmt->fetch()['pending_investments'];
            
            $stmt = $conn->query("SELECT COUNT(*) as pending_deposits FROM deposits WHERE status = 'pending'");
            $pending_deposits = $stmt->fetch()['pending_deposits'];
            
            $stmt = $conn->query("SELECT COUNT(*) as pending_withdrawals FROM withdrawal_requests WHERE status = 'pending'");
            $pending_withdrawals = $stmt->fetch()['pending_withdrawals'];

            // Platform earnings (fees)
            $stmt = $conn->query("SELECT COALESCE(SUM(fee), 0) as platform_earnings FROM transactions WHERE type = 'withdrawal' AND status = 'completed'");
            $platform_earnings = $stmt->fetch()['platform_earnings'];

            Response::success([
                'total_users' => $total_users,
                'total_investments' => $investment_stats['total_investments'],
                'total_invested' => $investment_stats['total_invested'],
                'total_deposits' => $deposit_stats['total_deposits'],
                'total_deposited' => $deposit_stats['total_deposited'],
                'total_withdrawals' => $withdrawal_stats['total_withdrawals'],
                'total_withdrawn' => $withdrawal_stats['total_withdrawn'],
                'pending_investments' => $pending_investments,
                'pending_deposits' => $pending_deposits,
                'pending_withdrawals' => $pending_withdrawals,
                'platform_earnings' => $platform_earnings
            ]);

        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function getUsers($page = 1, $filters = []) {
        try {
            $users = $this->userModel->getAllUsers($page, 20, $filters);
            $total = $this->userModel->getTotalUsersCount($filters);
            
            Response::success([
                'users' => $users,
                'total' => $total,
                'page' => $page,
                'per_page' => 20
            ]);
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }

    public function calculateDailyInterest() {
        try {
            $result = $this->investmentModel->calculateDailyInterest();
            Response::success([
                'processed_investments' => $result
            ], 'Daily interest calculation completed');
        } catch (Exception $e) {
            Response::error($e->getMessage());
        }
    }
}

class Application {
    private $db;
    private $authController;
    private $investmentController;
    private $transactionController;
    private $depositController;
    private $withdrawalController;
    private $referralController;
    private $kycController;
    private $supportController;
    private $twoFactorController;
    private $adminController;

    public function __construct() {
        $database = new Database();
        $this->db = $database->getConnection();
        
        $this->authController = new AuthController($this->db);
        $this->investmentController = new InvestmentController($this->db);
        $this->transactionController = new TransactionController($this->db);
        $this->depositController = new DepositController($this->db);
        $this->withdrawalController = new WithdrawalController($this->db);
        $this->referralController = new ReferralController($this->db);
        $this->kycController = new KYCController($this->db);
        $this->supportController = new SupportController($this->db);
        $this->twoFactorController = new TwoFactorController($this->db);
        $this->adminController = new AdminController($this->db);
    }

    public function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        // Remove /index.php from path if present
        $path = str_replace('/index.php', '', $path);
        
        try {
            $input = $this->getInputData();
            $files = $_FILES;

            error_log("API Request: $method $path");

            // CSRF protection for state-changing requests
            if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
                $csrf_token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $input['csrf_token'] ?? '';
                if (!Security::verifyCSRFToken($csrf_token)) {
                    Response::error('Invalid CSRF token', 403);
                }
            }

            switch ($path) {
                // Authentication endpoints
                case '/api/register':
                    if ($method === 'POST') $this->authController->register($input);
                    break;

                case '/api/login':
                    if ($method === 'POST') $this->authController->login($input);
                    break;

                case '/api/profile':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->authController->getProfile($user['user_id']);
                    elseif ($method === 'PUT') $this->authController->updateProfile($user['user_id'], $input, $files);
                    break;

                case '/api/profile/password':
                    $user = $this->authenticate();
                    if ($method === 'PUT') $this->authController->changePassword($user['user_id'], $input);
                    break;

                // Investment endpoints
                case '/api/investment-plans':
                    if ($method === 'GET') $this->investmentController->getPlans();
                    break;

                case '/api/investments':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->investmentController->getUserInvestments($user['user_id'], $_GET['page'] ?? 1);
                    elseif ($method === 'POST') $this->investmentController->createInvestment($user['user_id'], $input, $files);
                    break;

                case '/api/investments/active':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->investmentController->getActiveInvestments($user['user_id']);
                    break;

                // Transaction endpoints
                case '/api/transactions':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->transactionController->getUserTransactions($user['user_id'], $_GET['page'] ?? 1);
                    break;

                // Deposit endpoints
                case '/api/deposits':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->depositController->getUserDeposits($user['user_id'], $_GET['page'] ?? 1);
                    elseif ($method === 'POST') $this->depositController->createDeposit($user['user_id'], $input, $files);
                    break;

                // Withdrawal endpoints
                case '/api/withdrawals':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->withdrawalController->getUserWithdrawals($user['user_id'], $_GET['page'] ?? 1);
                    elseif ($method === 'POST') $this->withdrawalController->createWithdrawal($user['user_id'], $input);
                    break;

                // Referral endpoints
                case '/api/referrals/stats':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->referralController->getReferralStats($user['user_id']);
                    break;

                // KYC endpoints
                case '/api/kyc':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->kycController->getKYCStatus($user['user_id']);
                    elseif ($method === 'POST') $this->kycController->submitKYC($user['user_id'], $input, $files);
                    break;

                // Support endpoints
                case '/api/support':
                    $user = $this->authenticate();
                    if ($method === 'GET') $this->supportController->getUserTickets($user['user_id'], $_GET['page'] ?? 1);
                    elseif ($method === 'POST') $this->supportController->createTicket($user['user_id'], $input);
                    break;

                // 2FA endpoints
                case '/api/2fa/setup':
                    $user = $this->authenticate();
                    if ($method === 'POST') $this->twoFactorController->setup2FA($user['user_id']);
                    break;

                case '/api/2fa/verify':
                    $user = $this->authenticate();
                    if ($method === 'POST') $this->twoFactorController->verify2FA($user['user_id'], $input);
                    break;

                case '/api/2fa/disable':
                    $user = $this->authenticate();
                    if ($method === 'POST') $this->twoFactorController->disable2FA($user['user_id'], $input);
                    break;

                // Admin endpoints
                case '/api/admin/dashboard':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->adminController->getDashboardStats();
                    break;

                case '/api/admin/users':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->adminController->getUsers($_GET['page'] ?? 1, $_GET);
                    break;

                case '/api/admin/investments/pending':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->investmentController->getPendingInvestments();
                    break;

                case '/api/admin/investments/approve':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->investmentController->approveInvestment($input['investment_id'], $user['user_id']);
                    break;

                case '/api/admin/investments/reject':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->investmentController->rejectInvestment($input['investment_id'], $user['user_id']);
                    break;

                case '/api/admin/deposits/pending':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->depositController->getPendingDeposits();
                    break;

                case '/api/admin/deposits/approve':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->depositController->approveDeposit($input['deposit_id'], $user['user_id']);
                    break;

                case '/api/admin/deposits/reject':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->depositController->rejectDeposit($input['deposit_id'], $user['user_id'], $input);
                    break;

                case '/api/admin/withdrawals/pending':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->withdrawalController->getPendingWithdrawals();
                    break;

                case '/api/admin/withdrawals/approve':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->withdrawalController->approveWithdrawal($input['withdrawal_id'], $user['user_id']);
                    break;

                case '/api/admin/withdrawals/reject':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->withdrawalController->rejectWithdrawal($input['withdrawal_id'], $user['user_id'], $input);
                    break;

                case '/api/admin/kyc/pending':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->kycController->getPendingSubmissions();
                    break;

                case '/api/admin/kyc/approve':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->kycController->approveKYC($input['submission_id'], $user['user_id']);
                    break;

                case '/api/admin/kyc/reject':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->kycController->rejectKYC($input['submission_id'], $user['user_id'], $input);
                    break;

                case '/api/admin/support/tickets':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') $this->supportController->getAllTickets($_GET['page'] ?? 1, $_GET);
                    break;

                case '/api/admin/support/tickets/update':
                    $user = $this->authenticateAdmin();
                    if ($method === 'PUT') $this->supportController->updateTicketStatus($input['ticket_id'], $input);
                    break;

                case '/api/admin/calculate-interest':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') $this->adminController->calculateDailyInterest();
                    break;

                // CSRF token endpoint
                case '/api/csrf-token':
                    if ($method === 'GET') Response::csrfToken();
                    break;

                // Health check
                case '/api/health':
                    if ($method === 'GET') Response::success([
                        'status' => 'healthy', 
                        'version' => APP_VERSION,
                        'timestamp' => time(),
                        'environment' => 'production'
                    ]);
                    break;

                // File serving
                default:
                    if (preg_match('#^/api/files/(proofs|kyc|avatars)/(.+)$#', $path, $matches)) {
                        $this->serveFile($matches[1], $matches[2]);
                        break;
                    }
                    
                    Response::error('Endpoint not found: ' . $path, 404);
            }
        } catch (Exception $e) {
            error_log("Application error: " . $e->getMessage());
            Response::error('Internal server error', 500);
        }
    }

    private function getInputData() {
        $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
        
        if (strpos($content_type, 'application/json') !== false) {
            $input = json_decode(file_get_contents('php://input'), true) ?? [];
            return $input;
        } elseif (strpos($content_type, 'multipart/form-data') !== false) {
            return $_POST;
        } else {
            return $_POST;
        }
    }

    private function authenticate() {
        $headers = getallheaders();
        $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        
        if (empty($auth_header)) {
            Response::error('Authorization header missing', 401);
        }

        $token = str_replace('Bearer ', '', $auth_header);
        $user = Security::verifyToken($token);
        
        if (!$user) {
            Response::error('Invalid or expired token', 401);
        }

        return $user;
    }

    private function authenticateAdmin() {
        $user = $this->authenticate();
        
        if (!in_array($user['role'], ['admin', 'super_admin'])) {
            Response::error('Admin access required', 403);
        }

        return $user;
    }

    private function serveFile($type, $filename) {
        $file_path = UPLOAD_PATH . $type . '/' . $filename;
        
        if (!file_exists($file_path)) {
            Response::error('File not found', 404);
        }

        $real_path = realpath($file_path);
        $base_path = realpath(UPLOAD_PATH . $type . '/');
        
        if (strpos($real_path, $base_path) !== 0) {
            Response::error('Access denied', 403);
        }

        Response::file($file_path, $filename);
    }
}

// Initialize and run the application
try {
    $app = new Application();
    $app->handleRequest();
} catch (Exception $e) {
    Response::error('Application startup failed: ' . $e->getMessage(), 500);
}
?>

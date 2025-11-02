<?php
/* 
 * Raw Wealthy Investment Platform - Enterprise Production Edition
 * Advanced Platform with Complete Feature Set in Single File
 * Enhanced Security, Performance, Scalability, and Profitability Features
 * Market-Ready with Advanced Investment Algorithms - Naira Edition
 */

// Strict error reporting for production
error_reporting(E_ALL);
ini_set('display_errors', 0); // Disable in production
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Start session with enhanced security
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true
]);

// Define enterprise-grade constants
define('APP_NAME', 'Raw Wealthy Investment Platform');
define('APP_VERSION', '4.0.0');
define('BASE_URL', 'https://' . $_SERVER['HTTP_HOST'] . '/');
define('UPLOAD_PATH', realpath(dirname(__FILE__) . '/uploads') . '/');
define('MAX_FILE_SIZE', 50 * 1024 * 1024); // 50MB
define('JWT_SECRET', getenv('JWT_SECRET') ?: 'enterprise-secure-key-2024-change-in-production');
define('JWT_EXPIRY', 86400); // 24 hours
define('REFERRAL_BONUS_RATE', 0.20); // Increased to 20%
define('WITHDRAWAL_FEE_RATE', 0.05); // 5% withdrawal fee
define('MIN_DEPOSIT', 3500); // 3,500 Naira minimum
define('MIN_WITHDRAWAL', 3500); // 3,500 Naira minimum
define('MAX_WITHDRAWAL', 500000); // 500,000 Naira maximum
define('DAILY_PROFIT_RATE', 0.035); // 3.5% daily
define('COMPOUND_INTEREST_RATE', 0.02); // 2% compound
define('RISK_MANAGEMENT_BUFFER', 0.10); // 10% risk buffer

// Advanced security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// CORS headers for modern applications
header("Access-Control-Allow-Origin: " . (filter_var($_SERVER['HTTP_ORIGIN'] ?? '*', FILTER_SANITIZE_URL)));
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-API-Key, X-CSRF-Token");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Max-Age: 86400");

// Enterprise Database Configuration
class Database {
    private $host = 'localhost';
    private $db_name = 'raw_wealthy_enterprise_ngn';
    private $username = 'root';
    private $password = '';
    private $port = 3306;
    private $charset = 'utf8mb4';
    public $conn;
    private $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => true,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        PDO::MYSQL_ATTR_COMPRESS => true,
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
    ];

    public function getConnection() {
        $this->conn = null;
        try {
            $dsn = "mysql:host={$this->host};port={$this->port};dbname={$this->db_name};charset={$this->charset}";
            $this->conn = new PDO($dsn, $this->username, $this->password, $this->options);
            
            // Test connection
            $this->conn->query("SELECT 1");
        } catch(PDOException $exception) {
            error_log("Database connection error: " . $exception->getMessage());
            throw new Exception("Database connection failed. Please try again later.");
        }
        return $this->conn;
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

    public function getLastInsertId() {
        return $this->conn->lastInsertId();
    }
}

// Advanced Security Utilities with Enhanced Protection
class Security {
    private static $encryption_key = 'your-32-character-encryption-key-here';
    private static $cipher = "AES-256-CBC";
    
    public static function generateToken($payload) {
        $header = ['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'rawwealthy2024'];
        $payload['iss'] = BASE_URL;
        $payload['aud'] = BASE_URL;
        $payload['iat'] = time();
        $payload['exp'] = time() + JWT_EXPIRY;
        $payload['jti'] = bin2hex(random_bytes(16));
        $payload['nbf'] = time() - 60; // Not before 1 minute ago

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
                throw new Exception('Invalid token format');
            }

            list($encoded_header, $encoded_payload, $encoded_signature) = $parts;

            $header = json_decode(self::base64UrlDecode($encoded_header), true);
            $payload = json_decode(self::base64UrlDecode($encoded_payload), true);
            $signature = self::base64UrlDecode($encoded_signature);

            if (!$header || !$payload) {
                throw new Exception('Invalid token encoding');
            }

            if ($header['alg'] !== 'HS256') {
                throw new Exception('Unsupported algorithm');
            }

            $expected_signature = hash_hmac('sha256', $encoded_header . '.' . $encoded_payload, JWT_SECRET, true);
            if (!hash_equals($expected_signature, $signature)) {
                throw new Exception('Invalid signature');
            }

            // Validate timestamps
            $current_time = time();
            if (isset($payload['nbf']) && $payload['nbf'] > $current_time) {
                throw new Exception('Token not yet valid');
            }

            if (isset($payload['exp']) && $payload['exp'] < $current_time) {
                throw new Exception('Token expired');
            }

            return $payload;
        } catch (Exception $e) {
            error_log("JWT Verification Error: " . $e->getMessage());
            return false;
        }
    }

    public static function encryptData($data) {
        $iv_length = openssl_cipher_iv_length(self::$cipher);
        $iv = openssl_random_bytes($iv_length);
        $encrypted = openssl_encrypt($data, self::$cipher, self::$encryption_key, 0, $iv);
        return base64_encode($encrypted . '::' . $iv);
    }

    public static function decryptData($data) {
        list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
        return openssl_decrypt($encrypted_data, self::$cipher, self::$encryption_key, 0, $iv);
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

    public static function generateReferralCode() {
        $prefix = 'RW';
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $code = '';
        
        for ($i = 0; $i < 8; $i++) {
            $code .= $characters[random_int(0, strlen($characters) - 1)];
        }
        
        return $prefix . $code;
    }

    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        return $data;
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function generateRandomString($length = 32) {
        return bin2hex(random_bytes($length / 2));
    }

    public static function validateCSRF($token) {
        if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
            return false;
        }
        // Regenerate token after validation
        unset($_SESSION['csrf_token']);
        return true;
    }

    public static function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function rateLimit($key, $max_attempts = 10, $time_window = 900) {
        $rate_limit_key = "rate_limit:{$key}";
        $now = time();
        
        if (!isset($_SESSION[$rate_limit_key])) {
            $_SESSION[$rate_limit_key] = [
                'attempts' => 1,
                'first_attempt' => $now,
                'last_attempt' => $now,
                'blocked_until' => null
            ];
            return true;
        }
        
        $rate_data = $_SESSION[$rate_limit_key];
        
        // Check if still blocked
        if ($rate_data['blocked_until'] && $now < $rate_data['blocked_until']) {
            return false;
        }
        
        // Reset if time window passed
        if ($now - $rate_data['first_attempt'] > $time_window) {
            $_SESSION[$rate_limit_key] = [
                'attempts' => 1,
                'first_attempt' => $now,
                'last_attempt' => $now,
                'blocked_until' => null
            ];
            return true;
        }
        
        if ($rate_data['attempts'] >= $max_attempts) {
            // Block for 1 hour
            $_SESSION[$rate_limit_key]['blocked_until'] = $now + 3600;
            return false;
        }
        
        $rate_data['attempts']++;
        $rate_data['last_attempt'] = $now;
        $_SESSION[$rate_limit_key] = $rate_data;
        
        return true;
    }

    public static function getClientIP() {
        $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER)) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public static function validateFileUpload($file) {
        $errors = [];
        
        // Check file size
        if ($file['size'] > MAX_FILE_SIZE) {
            $errors[] = "File size exceeds maximum allowed size of " . (MAX_FILE_SIZE / 1024 / 1024) . "MB";
        }
        
        // Check for upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errors[] = "File upload error: " . $file['error'];
        }
        
        // Validate MIME type
        $allowed_types = [
            'image/jpeg', 'image/png', 'image/jpg', 'image/gif', 'image/webp',
            'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mime_type, $allowed_types)) {
            $errors[] = "File type not allowed. Allowed types: JPEG, PNG, GIF, WebP, PDF, DOC, DOCX";
        }
        
        // Check file extension
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'doc', 'docx'];
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($file_extension, $allowed_extensions)) {
            $errors[] = "File extension not allowed";
        }
        
        // Check for malicious content in images
        if (strpos($mime_type, 'image/') === 0) {
            $image_info = getimagesize($file['tmp_name']);
            if ($image_info === false) {
                $errors[] = "Invalid image file";
            }
        }
        
        // Check for PHP tags in files
        $file_content = file_get_contents($file['tmp_name']);
        if (preg_match('/<\?php|<\?=|script|eval\(|base64_decode/i', $file_content)) {
            $errors[] = "File contains potentially dangerous content";
        }
        
        return $errors;
    }

    public static function generate2FACode() {
        return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    public static function verify2FA($user_code, $secret) {
        // Implement TOTP verification
        $current_time = floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            $time = $current_time + $i;
            $expected_code = self::generateTOTP($secret, $time);
            if (hash_equals($expected_code, $user_code)) {
                return true;
            }
        }
        return false;
    }

    private static function generateTOTP($secret, $time) {
        $hmac = hash_hmac('sha1', pack('J', $time), $secret, true);
        $offset = ord($hmac[19]) & 0xf;
        $code = (
            ((ord($hmac[$offset]) & 0x7f) << 24) |
            ((ord($hmac[$offset + 1]) & 0xff) << 16) |
            ((ord($hmac[$offset + 2]) & 0xff) << 8) |
            (ord($hmac[$offset + 3]) & 0xff)
        ) % 1000000;
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
}

// Advanced Response Handler with Caching Support
class Response {
    private static $cache_enabled = true;
    private static $cache_time = 300; // 5 minutes

    public static function send($data, $status = 200, $cache_key = null) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        
        // Add caching headers
        if (self::$cache_enabled && $cache_key) {
            header('Cache-Control: public, max-age=' . self::$cache_time);
            header('ETag: "' . md5(serialize($data)) . '"');
        } else {
            header('Cache-Control: no-cache, no-store, must-revalidate');
        }
        
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public static function error($message, $status = 400, $code = null, $details = []) {
        $response = [
            'success' => false,
            'message' => $message,
            'timestamp' => time(),
            'status' => $status,
            'request_id' => self::generateRequestId()
        ];
        
        if ($code !== null) {
            $response['code'] = $code;
        }
        
        if (!empty($details)) {
            $response['details'] = $details;
        }
        
        self::logError($message, $status, $code, $details);
        self::send($response, $status);
    }

    public static function success($data = [], $message = '', $cache_key = null) {
        $response = [
            'success' => true,
            'timestamp' => time(),
            'request_id' => self::generateRequestId()
        ];
        
        if ($message) {
            $response['message'] = $message;
        }
        
        if ($data) {
            $response['data'] = $data;
        }
        
        self::send($response, 200, $cache_key);
    }

    public static function validationError($errors) {
        self::send([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $errors,
            'timestamp' => time(),
            'request_id' => self::generateRequestId()
        ], 422);
    }

    public static function paginated($data, $total, $page, $per_page, $message = '') {
        $response = [
            'success' => true,
            'data' => $data,
            'pagination' => [
                'total' => $total,
                'page' => $page,
                'per_page' => $per_page,
                'total_pages' => ceil($total / $per_page),
                'has_more' => ($page * $per_page) < $total
            ],
            'timestamp' => time(),
            'request_id' => self::generateRequestId()
        ];
        
        if ($message) {
            $response['message'] = $message;
        }
        
        self::send($response);
    }

    private static function generateRequestId() {
        return bin2hex(random_bytes(8)) . '-' . time();
    }

    private static function logError($message, $status, $code, $details) {
        $log_data = [
            'timestamp' => date('Y-m-d H:i:s'),
            'request_id' => self::generateRequestId(),
            'status' => $status,
            'code' => $code,
            'message' => $message,
            'details' => $details,
            'ip' => Security::getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ];
        
        error_log("API Error: " . json_encode($log_data));
    }
}

// Enhanced User Model with Advanced Features
class User {
    private $conn;
    private $table_name = "users";

    public $id;
    public $full_name;
    public $email;
    public $phone;
    public $password_hash;
    public $balance;
    public $total_invested;
    public $total_earnings;
    public $referral_earnings;
    public $referral_code;
    public $referred_by;
    public $role;
    public $kyc_verified;
    public $status;
    public $last_login;
    public $login_attempts;
    public $locked_until;
    public $two_factor_enabled;
    public $two_factor_secret;
    public $risk_tolerance;
    public $investment_strategy;
    public $created_at;
    public $updated_at;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create() {
        try {
            $this->conn->beginTransaction();

            $query = "INSERT INTO " . $this->table_name . " 
                    SET full_name=:full_name, email=:email, phone=:phone, 
                    password_hash=:password_hash, referral_code=:referral_code, 
                    referred_by=:referred_by, balance=:balance, total_invested=0, 
                    total_earnings=0, referral_earnings=0, two_factor_secret=:two_factor_secret,
                    risk_tolerance=:risk_tolerance, investment_strategy=:investment_strategy";

            $stmt = $this->conn->prepare($query);

            $this->full_name = Security::sanitizeInput($this->full_name);
            $this->email = Security::sanitizeInput($this->email);
            $this->phone = Security::sanitizeInput($this->phone);

            // Set initial balance with welcome bonus
            $initial_balance = 5000.00; // 5,000 Naira Welcome bonus
            $two_factor_secret = bin2hex(random_bytes(20));
            $risk_tolerance = $this->risk_tolerance ?? 'medium';
            $investment_strategy = $this->investment_strategy ?? 'balanced';

            $stmt->bindParam(":full_name", $this->full_name);
            $stmt->bindParam(":email", $this->email);
            $stmt->bindParam(":phone", $this->phone);
            $stmt->bindParam(":password_hash", $this->password_hash);
            $stmt->bindParam(":referral_code", $this->referral_code);
            $stmt->bindParam(":referred_by", $this->referred_by);
            $stmt->bindParam(":balance", $initial_balance);
            $stmt->bindParam(":two_factor_secret", $two_factor_secret);
            $stmt->bindParam(":risk_tolerance", $risk_tolerance);
            $stmt->bindParam(":investment_strategy", $investment_strategy);

            if($stmt->execute()) {
                $this->id = $this->conn->lastInsertId();
                
                // Process referral bonus if applicable
                if ($this->referred_by) {
                    $this->processReferralBonus($this->referred_by, $this->id);
                }

                $this->createNotification(
                    $this->id,
                    "🎉 Welcome to Raw Wealthy!",
                    "Thank you for registering! You've received ₦5,000 welcome bonus. Start your investment journey today!",
                    'success'
                );

                // Log registration
                $this->logActivity($this->id, 'registration', 'User registered successfully with welcome bonus');

                $this->conn->commit();
                return true;
            }
            
            $this->conn->rollBack();
            return false;
        } catch (Exception $e) {
            $this->conn->rollBack();
            error_log("User creation error: " . $e->getMessage());
            throw new Exception("User registration failed: " . $e->getMessage());
        }
    }

    public function emailExists() {
        $query = "SELECT id, full_name, password_hash, role, status, balance, 
                         referral_code, login_attempts, locked_until, two_factor_enabled,
                         two_factor_secret, risk_tolerance, investment_strategy
                FROM " . $this->table_name . " 
                WHERE email = ? 
                LIMIT 0,1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->email);
        $stmt->execute();

        if($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($row['locked_until'] && strtotime($row['locked_until']) > time()) {
                $lock_time = strtotime($row['locked_until']) - time();
                throw new Exception("Account temporarily locked. Try again in " . ceil($lock_time/60) . " minutes.");
            }

            $this->id = $row['id'];
            $this->full_name = $row['full_name'];
            $this->password_hash = $row['password_hash'];
            $this->role = $row['role'];
            $this->status = $row['status'];
            $this->balance = $row['balance'];
            $this->referral_code = $row['referral_code'];
            $this->login_attempts = $row['login_attempts'];
            $this->locked_until = $row['locked_until'];
            $this->two_factor_enabled = $row['two_factor_enabled'];
            $this->two_factor_secret = $row['two_factor_secret'];
            $this->risk_tolerance = $row['risk_tolerance'];
            $this->investment_strategy = $row['investment_strategy'];
            return true;
        }
        return false;
    }

    public function updateBalance($amount, $transaction_type = 'adjustment', $description = '') {
        $query = "UPDATE " . $this->table_name . " 
                SET balance = balance + ?, updated_at = NOW() 
                WHERE id = ?";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $amount);
        $stmt->bindParam(2, $this->id);

        if ($stmt->execute()) {
            $this->logBalanceChange($amount, $transaction_type, $description);
            
            // Update user stats based on transaction type
            $this->updateUserStats($amount, $transaction_type);
            
            return true;
        }
        return false;
    }

    public function getByReferralCode($referral_code) {
        $query = "SELECT id, full_name, email, balance FROM " . $this->table_name . " 
                WHERE referral_code = ? AND status = 'active'
                LIMIT 0,1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $referral_code);
        $stmt->execute();

        if($stmt->rowCount() > 0) {
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }
        return false;
    }

    public function readOne() {
        $query = "SELECT * FROM " . $this->table_name . " 
                WHERE id = ? 
                LIMIT 0,1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->id);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if($row) {
            $this->full_name = $row['full_name'];
            $this->email = $row['email'];
            $this->phone = $row['phone'];
            $this->balance = $row['balance'];
            $this->total_invested = $row['total_invested'];
            $this->total_earnings = $row['total_earnings'];
            $this->referral_earnings = $row['referral_earnings'];
            $this->referral_code = $row['referral_code'];
            $this->referred_by = $row['referred_by'];
            $this->role = $row['role'];
            $this->kyc_verified = $row['kyc_verified'];
            $this->status = $row['status'];
            $this->last_login = $row['last_login'];
            $this->two_factor_enabled = $row['two_factor_enabled'];
            $this->risk_tolerance = $row['risk_tolerance'];
            $this->investment_strategy = $row['investment_strategy'];
            $this->created_at = $row['created_at'];
            return true;
        }
        return false;
    }

    public function updateProfile($data) {
        $query = "UPDATE " . $this->table_name . " 
                SET full_name=:full_name, phone=:phone, risk_tolerance=:risk_tolerance,
                investment_strategy=:investment_strategy, updated_at = NOW()
                WHERE id=:id";

        $stmt = $this->conn->prepare($query);
        $risk_tolerance = $data['risk_tolerance'] ?? $this->risk_tolerance;
        $investment_strategy = $data['investment_strategy'] ?? $this->investment_strategy;

        $stmt->bindParam(":full_name", $data['full_name']);
        $stmt->bindParam(":phone", $data['phone']);
        $stmt->bindParam(":risk_tolerance", $risk_tolerance);
        $stmt->bindParam(":investment_strategy", $investment_strategy);
        $stmt->bindParam(":id", $this->id);

        return $stmt->execute();
    }

    public function updateLoginAttempts($success = true) {
        if ($success) {
            $query = "UPDATE " . $this->table_name . " 
                    SET login_attempts = 0, locked_until = NULL, last_login = NOW() 
                    WHERE id = ?";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(1, $this->id);
        } else {
            $new_attempts = $this->login_attempts + 1;
            $locked_until = null;
            
            if ($new_attempts >= 5) {
                $locked_until = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            }
            
            $query = "UPDATE " . $this->table_name . " 
                    SET login_attempts = ?, locked_until = ? 
                    WHERE id = ?";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(1, $new_attempts);
            $stmt->bindParam(2, $locked_until);
            $stmt->bindParam(3, $this->id);
        }

        return $stmt->execute();
    }

    public function getDashboardStats($user_id) {
        $stats = [];
        
        // Active investments count and value
        $query = "SELECT COUNT(*) as active_investments, COALESCE(SUM(amount), 0) as active_investment_value 
                 FROM investments 
                 WHERE user_id = ? AND status = 'active'";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $investment_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['active_investments'] = $investment_stats['active_investments'];
        $stats['active_investment_value'] = $investment_stats['active_investment_value'];

        // Total referrals
        $query = "SELECT COUNT(*) as total_referrals FROM users 
                 WHERE referred_by = (SELECT referral_code FROM users WHERE id = ?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['total_referrals'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_referrals'];

        // Today's earnings
        $query = "SELECT COALESCE(SUM(amount), 0) as today_earnings FROM daily_earnings 
                 WHERE user_id = ? AND earning_date = CURDATE()";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['today_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['today_earnings'];

        // Pending withdrawals
        $query = "SELECT COALESCE(SUM(amount), 0) as pending_withdrawals FROM withdrawal_requests 
                 WHERE user_id = ? AND status = 'pending'";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['pending_withdrawals'] = $stmt->fetch(PDO::FETCH_ASSOC)['pending_withdrawals'];

        // Weekly earnings
        $query = "SELECT COALESCE(SUM(amount), 0) as weekly_earnings FROM daily_earnings 
                 WHERE user_id = ? AND earning_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['weekly_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['weekly_earnings'];

        // Monthly earnings
        $query = "SELECT COALESCE(SUM(amount), 0) as monthly_earnings FROM daily_earnings 
                 WHERE user_id = ? AND MONTH(earning_date) = MONTH(CURDATE()) AND YEAR(earning_date) = YEAR(CURDATE())";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['monthly_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['monthly_earnings'];

        return $stats;
    }

    public function enable2FA($user_id) {
        $secret = bin2hex(random_bytes(20));
        $query = "UPDATE " . $this->table_name . " 
                 SET two_factor_enabled = TRUE, two_factor_secret = ? 
                 WHERE id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $secret);
        $stmt->bindParam(2, $user_id);
        
        if ($stmt->execute()) {
            return $secret;
        }
        return false;
    }

    public function disable2FA($user_id) {
        $query = "UPDATE " . $this->table_name . " 
                 SET two_factor_enabled = FALSE, two_factor_secret = NULL 
                 WHERE id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        
        return $stmt->execute();
    }

    public function verify2FA($user_id, $code) {
        $query = "SELECT two_factor_secret FROM " . $this->table_name . " 
                 WHERE id = ? AND two_factor_enabled = TRUE";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        
        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return Security::verify2FA($code, $row['two_factor_secret']);
        }
        
        return false;
    }

    private function processReferralBonus($referral_code, $new_user_id) {
        $referrer = $this->getByReferralCode($referral_code);
        if ($referrer) {
            $bonus_amount = 2000.00; // ₦2,000 referral bonus
            
            $query = "UPDATE " . $this->table_name . " 
                     SET referral_earnings = referral_earnings + ?, balance = balance + ?
                     WHERE id = ?";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(1, $bonus_amount);
            $stmt->bindParam(2, $bonus_amount);
            $stmt->bindParam(3, $referrer['id']);
            
            if ($stmt->execute()) {
                $this->createNotification(
                    $referrer['id'],
                    "🎊 Referral Bonus!",
                    "You've received ₦2,000 bonus for referring " . $this->full_name . "!",
                    'success'
                );
                
                $this->logActivity($referrer['id'], 'referral_bonus', "Received referral bonus for user $new_user_id");
            }
        }
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications 
                 SET user_id=:user_id, title=:title, message=:message, type=:type, priority=:priority";
        
        $priority = $type === 'success' ? 'high' : 'medium';
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":type", $type);
        $stmt->bindParam(":priority", $priority);
        
        return $stmt->execute();
    }

    private function logBalanceChange($amount, $transaction_type, $description = '') {
        $query = "INSERT INTO audit_logs 
                 SET user_id=:user_id, action=:action, description=:description,
                 ip_address=:ip_address, user_agent=:user_agent, metadata=:metadata";
        
        $stmt = $this->conn->prepare($query);
        $action = 'balance_update';
        $full_description = "Balance {$transaction_type}: " . ($amount >= 0 ? '+' : '') . number_format($amount, 2);
        if ($description) {
            $full_description .= " - " . $description;
        }
        $ip_address = Security::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $metadata = json_encode(['amount' => $amount, 'type' => $transaction_type]);
        
        $stmt->bindParam(":user_id", $this->id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":description", $full_description);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        $stmt->bindParam(":metadata", $metadata);
        
        $stmt->execute();
    }

    private function updateUserStats($amount, $transaction_type) {
        $query = "";
        switch ($transaction_type) {
            case 'investment':
                $query = "UPDATE " . $this->table_name . " 
                         SET total_invested = total_invested + ? 
                         WHERE id = ?";
                break;
            case 'earning':
                $query = "UPDATE " . $this->table_name . " 
                         SET total_earnings = total_earnings + ? 
                         WHERE id = ?";
                break;
            case 'referral':
                $query = "UPDATE " . $this->table_name . " 
                         SET referral_earnings = referral_earnings + ? 
                         WHERE id = ?";
                break;
        }
        
        if ($query) {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(1, $amount);
            $stmt->bindParam(2, $this->id);
            $stmt->execute();
        }
    }

    private function logActivity($user_id, $action, $description) {
        $query = "INSERT INTO audit_logs 
                 SET user_id=:user_id, action=:action, description=:description,
                 ip_address=:ip_address, user_agent=:user_agent";
        
        $stmt = $this->conn->prepare($query);
        $ip_address = Security::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        
        $stmt->execute();
    }
}

// Advanced Investment Model with AI-Powered Features
class Investment {
    private $conn;
    private $table_name = "investments";

    public $id;
    public $user_id;
    public $plan_id;
    public $amount;
    public $daily_interest;
    public $total_interest;
    public $duration;
    public $start_date;
    public $end_date;
    public $status;
    public $proof_image;
    public $earnings_paid;
    public $expected_earnings;
    public $auto_renew;
    public $risk_level;
    public $profitability_score;
    public $market_trend;
    public $created_at;
    public $updated_at;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create() {
        try {
            $this->conn->beginTransaction();

            // Calculate expected earnings with AI-powered adjustments
            $this->expected_earnings = $this->calculateExpectedEarnings();
            $this->profitability_score = $this->calculateProfitabilityScore();
            $this->market_trend = $this->analyzeMarketTrend();

            $query = "INSERT INTO " . $this->table_name . " 
                    SET user_id=:user_id, plan_id=:plan_id, amount=:amount, 
                    daily_interest=:daily_interest, total_interest=:total_interest, 
                    duration=:duration, proof_image=:proof_image,
                    expected_earnings=:expected_earnings, auto_renew=:auto_renew,
                    risk_level=:risk_level, profitability_score=:profitability_score,
                    market_trend=:market_trend";

            $stmt = $this->conn->prepare($query);

            $stmt->bindParam(":user_id", $this->user_id);
            $stmt->bindParam(":plan_id", $this->plan_id);
            $stmt->bindParam(":amount", $this->amount);
            $stmt->bindParam(":daily_interest", $this->daily_interest);
            $stmt->bindParam(":total_interest", $this->total_interest);
            $stmt->bindParam(":duration", $this->duration);
            $stmt->bindParam(":proof_image", $this->proof_image);
            $stmt->bindParam(":expected_earnings", $this->expected_earnings);
            $stmt->bindParam(":auto_renew", $this->auto_renew);
            $stmt->bindParam(":risk_level", $this->risk_level);
            $stmt->bindParam(":profitability_score", $this->profitability_score);
            $stmt->bindParam(":market_trend", $this->market_trend);

            if($stmt->execute()) {
                $investment_id = $this->conn->lastInsertId();
                
                // Update user's total invested
                $user_update = $this->conn->prepare("UPDATE users SET total_invested = total_invested + ? WHERE id = ?");
                $user_update->bindParam(1, $this->amount);
                $user_update->bindParam(2, $this->user_id);
                $user_update->execute();

                $this->createNotification(
                    $this->user_id,
                    "📈 Investment Submitted",
                    "Your investment of ₦" . number_format($this->amount, 2) . " is under review. Expected earnings: ₦" . number_format($this->expected_earnings, 2),
                    'info'
                );

                $this->logActivity($this->user_id, 'investment_created', "Created investment with expected earnings: ₦" . $this->expected_earnings);

                $this->conn->commit();
                return $investment_id;
            }
            
            $this->conn->rollBack();
            return false;
        } catch (Exception $e) {
            $this->conn->rollBack();
            error_log("Investment creation error: " . $e->getMessage());
            throw new Exception("Investment creation failed: " . $e->getMessage());
        }
    }

    public function getActiveInvestments($user_id = null) {
        $query = "SELECT i.*, p.name as plan_name, p.description as plan_description,
                         p.risk_level as plan_risk, u.full_name, u.email
                FROM " . $this->table_name . " i 
                LEFT JOIN investment_plans p ON i.plan_id = p.id 
                LEFT JOIN users u ON i.user_id = u.id
                WHERE i.status = 'active'";

        if($user_id) {
            $query .= " AND i.user_id = :user_id";
        }

        $query .= " ORDER BY i.created_at DESC";

        $stmt = $this->conn->prepare($query);
        
        if($user_id) {
            $stmt->bindParam(":user_id", $user_id);
        }

        $stmt->execute();
        return $stmt;
    }

    public function updateStatus($investment_id, $status, $admin_id = null) {
        try {
            $this->conn->beginTransaction();

            $query = "UPDATE " . $this->table_name . " 
                    SET status = :status, updated_at = NOW()";

            if($status == 'active') {
                $query .= ", start_date = NOW(), end_date = DATE_ADD(NOW(), INTERVAL duration DAY)";
            } elseif ($status == 'completed') {
                $query .= ", earnings_paid = expected_earnings";
            }

            $query .= " WHERE id = :id";

            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":status", $status);
            $stmt->bindParam(":id", $investment_id);

            if($stmt->execute()) {
                // Get investment details for notification
                $investment = $this->getById($investment_id);
                
                if ($investment) {
                    $message = "Your investment has been " . $status;
                    if ($status == 'active') {
                        $message = "Your investment of ₦" . number_format($investment['amount'], 2) . " is now active!";
                    } elseif ($status == 'completed') {
                        $message = "Your investment has been completed. Total earnings: ₦" . number_format($investment['expected_earnings'], 2);
                    }
                    
                    $this->createNotification($investment['user_id'], "Investment " . ucfirst($status), $message, 'success');
                }

                if ($admin_id) {
                    $this->logAdminAction($admin_id, $investment_id, $status);
                }

                $this->conn->commit();
                return true;
            }
            
            $this->conn->rollBack();
            return false;
        } catch (Exception $e) {
            $this->conn->rollBack();
            error_log("Investment status update error: " . $e->getMessage());
            throw new Exception("Investment status update failed: " . $e->getMessage());
        }
    }

    public function getUserInvestments($user_id, $limit = null, $offset = 0) {
        $query = "SELECT i.*, p.name as plan_name, p.description as plan_description,
                         p.risk_level as plan_risk, p.min_amount, p.max_amount
                FROM " . $this->table_name . " i 
                LEFT JOIN investment_plans p ON i.plan_id = p.id 
                WHERE i.user_id = :user_id 
                ORDER BY i.created_at DESC";

        if ($limit) {
            $query .= " LIMIT :limit OFFSET :offset";
        }

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        
        if ($limit) {
            $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
        }

        $stmt->execute();
        return $stmt;
    }

    public function calculateDailyEarnings() {
        $query = "SELECT i.*, u.email, u.full_name, u.risk_tolerance
                 FROM investments i 
                 JOIN users u ON i.user_id = u.id 
                 WHERE i.status = 'active' 
                 AND i.end_date > NOW() 
                 AND DATEDIFF(NOW(), i.start_date) < i.duration";

        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        $earnings_created = 0;
        $today = date('Y-m-d');

        while ($investment = $stmt->fetch(PDO::FETCH_ASSOC)) {
            // Calculate base daily earning
            $base_earning = $investment['amount'] * ($investment['daily_interest'] / 100);
            
            // Apply risk-based adjustments
            $risk_adjustment = $this->calculateRiskAdjustment($investment['risk_tolerance']);
            $market_adjustment = $this->calculateMarketAdjustment($investment['market_trend']);
            
            $final_earning = $base_earning * $risk_adjustment * $market_adjustment;

            // Check if earnings already calculated for today
            $check_query = "SELECT id FROM daily_earnings 
                           WHERE investment_id = ? AND earning_date = ?";
            $check_stmt = $this->conn->prepare($check_query);
            $check_stmt->bindParam(1, $investment['id']);
            $check_stmt->bindParam(2, $today);
            $check_stmt->execute();

            if ($check_stmt->rowCount() == 0) {
                $earning_query = "INSERT INTO daily_earnings 
                                 SET user_id=:user_id, investment_id=:investment_id,
                                 amount=:amount, earning_date=:earning_date,
                                 base_amount=:base_amount, risk_adjustment=:risk_adjustment,
                                 market_adjustment=:market_adjustment";
                
                $earning_stmt = $this->conn->prepare($earning_query);
                $earning_stmt->bindParam(":user_id", $investment['user_id']);
                $earning_stmt->bindParam(":investment_id", $investment['id']);
                $earning_stmt->bindParam(":amount", $final_earning);
                $earning_stmt->bindParam(":earning_date", $today);
                $earning_stmt->bindParam(":base_amount", $base_earning);
                $earning_stmt->bindParam(":risk_adjustment", $risk_adjustment);
                $earning_stmt->bindParam(":market_adjustment", $market_adjustment);
                
                if ($earning_stmt->execute()) {
                    $earnings_created++;
                    
                    // Update investment earnings
                    $update_query = "UPDATE investments 
                                    SET earnings_paid = earnings_paid + ? 
                                    WHERE id = ?";
                    $update_stmt = $this->conn->prepare($update_query);
                    $update_stmt->bindParam(1, $final_earning);
                    $update_stmt->bindParam(2, $investment['id']);
                    $update_stmt->execute();
                    
                    // Update user balance and total earnings
                    $user_query = "UPDATE users 
                                  SET total_earnings = total_earnings + ?,
                                  balance = balance + ? 
                                  WHERE id = ?";
                    $user_stmt = $this->conn->prepare($user_query);
                    $user_stmt->bindParam(1, $final_earning);
                    $user_stmt->bindParam(2, $final_earning);
                    $user_stmt->bindParam(3, $investment['user_id']);
                    $user_stmt->execute();
                    
                    // Create earning notification
                    $this->createNotification(
                        $investment['user_id'],
                        "💰 Daily Earnings",
                        "You earned ₦" . number_format($final_earning, 2) . " from your investment today!",
                        'success'
                    );
                }
            }
        }

        return $earnings_created;
    }

    public function getInvestmentPerformance($user_id) {
        $query = "SELECT 
                    COUNT(*) as total_investments,
                    SUM(amount) as total_invested,
                    SUM(earnings_paid) as total_earned,
                    AVG(daily_interest) as avg_daily_return,
                    SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_investments,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_investments,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_investments,
                    MAX(profitability_score) as best_performing_score,
                    AVG(profitability_score) as avg_performance_score
                 FROM investments 
                 WHERE user_id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getPortfolioAnalysis($user_id) {
        $analysis = [];
        
        // Investment distribution by plan
        $query = "SELECT p.name, COUNT(i.id) as count, SUM(i.amount) as total_amount
                 FROM investments i
                 JOIN investment_plans p ON i.plan_id = p.id
                 WHERE i.user_id = ? AND i.status = 'active'
                 GROUP BY p.id, p.name";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $analysis['plan_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Risk distribution
        $query = "SELECT risk_level, COUNT(*) as count, SUM(amount) as total_amount
                 FROM investments
                 WHERE user_id = ? AND status = 'active'
                 GROUP BY risk_level";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $analysis['risk_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Monthly performance
        $query = "SELECT YEAR(earning_date) as year, MONTH(earning_date) as month, 
                         SUM(amount) as total_earnings
                 FROM daily_earnings
                 WHERE user_id = ?
                 GROUP BY YEAR(earning_date), MONTH(earning_date)
                 ORDER BY year DESC, month DESC
                 LIMIT 12";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $analysis['monthly_performance'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $analysis;
    }

    public function getInvestmentRecommendations($user_id) {
        $user = new User($this->conn);
        $user->id = $user_id;
        $user->readOne();

        $risk_tolerance = $user->risk_tolerance ?? 'medium';
        
        $query = "SELECT * FROM investment_plans 
                 WHERE status = 'active' 
                 AND risk_level = :risk_level
                 ORDER BY daily_interest DESC
                 LIMIT 3";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":risk_level", $risk_tolerance);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function calculateExpectedEarnings() {
        $base_earnings = $this->amount * ($this->total_interest / 100);
        
        // Apply compound interest for longer durations
        if ($this->duration > 30) {
            $compound_factor = pow(1 + COMPOUND_INTEREST_RATE, floor($this->duration / 30));
            $base_earnings *= $compound_factor;
        }
        
        // Apply risk adjustment
        $risk_adjustment = $this->getRiskAdjustment($this->risk_level);
        $base_earnings *= $risk_adjustment;
        
        return round($base_earnings, 2);
    }

    private function calculateProfitabilityScore() {
        $base_score = ($this->daily_interest * 10) + ($this->total_interest / 10);
        
        // Adjust based on risk
        $risk_multiplier = 1.0;
        switch ($this->risk_level) {
            case 'low': $risk_multiplier = 0.8; break;
            case 'medium': $risk_multiplier = 1.0; break;
            case 'high': $risk_multiplier = 1.3; break;
        }
        
        // Adjust based on amount (larger investments get better scores)
        $amount_multiplier = min(1.5, 1 + ($this->amount / 1000000));
        
        return round(($base_score * $risk_multiplier * $amount_multiplier), 2);
    }

    private function analyzeMarketTrend() {
        // Simulate market analysis - in production, this would integrate with real market data
        $trends = ['bullish', 'stable', 'volatile', 'bearish'];
        $weights = [40, 30, 20, 10]; // Probability weights
        
        $random = mt_rand(1, 100);
        $cumulative = 0;
        
        foreach ($weights as $index => $weight) {
            $cumulative += $weight;
            if ($random <= $cumulative) {
                return $trends[$index];
            }
        }
        
        return 'stable';
    }

    private function calculateRiskAdjustment($risk_tolerance) {
        $adjustments = [
            'low' => 0.9,    // Conservative - lower returns, lower risk
            'medium' => 1.0,  // Balanced
            'high' => 1.1     // Aggressive - higher returns, higher risk
        ];
        
        return $adjustments[$risk_tolerance] ?? 1.0;
    }

    private function calculateMarketAdjustment($market_trend) {
        $adjustments = [
            'bullish' => 1.15,   // 15% higher in bullish market
            'stable' => 1.0,     // No adjustment
            'volatile' => 0.9,   // 10% lower in volatile market
            'bearish' => 0.8     // 20% lower in bearish market
        ];
        
        return $adjustments[$market_trend] ?? 1.0;
    }

    private function getRiskAdjustment($risk_level) {
        $adjustments = [
            'low' => 0.85,
            'medium' => 1.0,
            'high' => 1.25
        ];
        
        return $adjustments[$risk_level] ?? 1.0;
    }

    private function getById($investment_id) {
        $query = "SELECT * FROM investments WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $investment_id);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications 
                 SET user_id=:user_id, title=:title, message=:message, type=:type, priority=:priority";
        
        $priority = $type === 'success' ? 'high' : 'medium';
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":type", $type);
        $stmt->bindParam(":priority", $priority);
        
        return $stmt->execute();
    }

    private function logAdminAction($admin_id, $investment_id, $action) {
        $query = "INSERT INTO audit_logs 
                 SET user_id=:user_id, action=:action, description=:description,
                 ip_address=:ip_address, user_agent=:user_agent";
        
        $stmt = $this->conn->prepare($query);
        $description = "Investment {$action}: ID {$investment_id}";
        $ip_address = Security::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt->bindParam(":user_id", $admin_id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        
        $stmt->execute();
    }

    private function logActivity($user_id, $action, $description) {
        $query = "INSERT INTO audit_logs 
                 SET user_id=:user_id, action=:action, description=:description,
                 ip_address=:ip_address, user_agent=:user_agent";
        
        $stmt = $this->conn->prepare($query);
        $ip_address = Security::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        
        $stmt->execute();
    }

    public function checkCompletion() {
        $query = "SELECT i.*, u.email, u.full_name 
                 FROM investments i 
                 JOIN users u ON i.user_id = u.id 
                 WHERE i.status = 'active' 
                 AND i.end_date <= NOW()";

        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        $completed = 0;

        while ($investment = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if ($this->updateStatus($investment['id'], 'completed')) {
                $completed++;
                
                if ($investment['auto_renew']) {
                    $this->autoRenewInvestment($investment);
                } else {
                    $this->createNotification(
                        $investment['user_id'],
                        "🎯 Investment Completed",
                        "Your investment in " . $investment['plan_name'] . " has been completed. Total earnings: ₦" . 
                        number_format($investment['earnings_paid'], 2),
                        'success'
                    );
                }
            }
        }

        return $completed;
    }

    private function autoRenewInvestment($investment) {
        $new_investment = new Investment($this->conn);
        $new_investment->user_id = $investment['user_id'];
        $new_investment->plan_id = $investment['plan_id'];
        $new_investment->amount = $investment['amount'] + $investment['earnings_paid']; // Compound
        $new_investment->daily_interest = $investment['daily_interest'];
        $new_investment->total_interest = $investment['total_interest'];
        $new_investment->duration = $investment['duration'];
        $new_investment->risk_level = $investment['risk_level'];
        $new_investment->auto_renew = true;

        if ($new_investment->create()) {
            $this->createNotification(
                $investment['user_id'],
                "🔄 Investment Auto-Renewed",
                "Your investment has been automatically renewed with compounded earnings! New amount: ₦" . 
                number_format($new_investment->amount, 2),
                'info'
            );
        }
    }
}

// Advanced Auth Controller with 2FA and Enhanced Security
class AuthController {
    private $db;
    private $user;

    public function __construct($db) {
        $this->db = $db;
        $this->user = new User($db);
    }

    public function register($data) {
        try {
            if (!Security::rateLimit('register_' . Security::getClientIP(), 3, 3600)) {
                Response::error('Too many registration attempts. Please try again later.', 429);
            }

            $errors = [];
            if (empty($data['full_name'])) $errors['full_name'] = 'Full name is required';
            if (empty($data['email'])) $errors['email'] = 'Email is required';
            if (empty($data['phone'])) $errors['phone'] = 'Phone is required';
            if (empty($data['password'])) $errors['password'] = 'Password is required';
            if (strlen($data['password']) < 8) $errors['password'] = 'Password must be at least 8 characters';
            if (!preg_match('/[A-Z]/', $data['password'])) $errors['password'] = 'Password must contain at least one uppercase letter';
            if (!preg_match('/[a-z]/', $data['password'])) $errors['password'] = 'Password must contain at least one lowercase letter';
            if (!preg_match('/[0-9]/', $data['password'])) $errors['password'] = 'Password must contain at least one number';

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            if (!Security::validateEmail($data['email'])) {
                Response::error('Invalid email format');
            }

            $this->user->email = Security::sanitizeInput($data['email']);
            if ($this->user->emailExists()) {
                Response::error('Email already registered');
            }

            $referred_by = null;
            if (!empty($data['referral_code'])) {
                $referrer = $this->user->getByReferralCode(Security::sanitizeInput($data['referral_code']));
                if (!$referrer) {
                    Response::error('Invalid referral code');
                }
                $referred_by = Security::sanitizeInput($data['referral_code']);
            }

            $this->user->full_name = Security::sanitizeInput($data['full_name']);
            $this->user->email = Security::sanitizeInput($data['email']);
            $this->user->phone = Security::sanitizeInput($data['phone']);
            $this->user->password_hash = Security::hashPassword($data['password']);
            $this->user->referral_code = Security::generateReferralCode();
            $this->user->referred_by = $referred_by;
            $this->user->risk_tolerance = $data['risk_tolerance'] ?? 'medium';
            $this->user->investment_strategy = $data['investment_strategy'] ?? 'balanced';

            if ($this->user->create()) {
                $token = Security::generateToken([
                    'user_id' => $this->user->id,
                    'email' => $this->user->email,
                    'role' => 'user'
                ]);

                $this->logActivity($this->user->id, 'registration', 'User registered successfully with welcome bonus');

                Response::success([
                    'token' => $token,
                    'user' => [
                        'id' => $this->user->id,
                        'full_name' => $this->user->full_name,
                        'email' => $this->user->email,
                        'referral_code' => $this->user->referral_code,
                        'balance' => $this->user->balance,
                        'kyc_verified' => $this->user->kyc_verified,
                        'risk_tolerance' => $this->user->risk_tolerance,
                        'investment_strategy' => $this->user->investment_strategy
                    ]
                ], 'Registration successful. Welcome to Raw Wealthy! You received ₦5,000 welcome bonus!');
            } else {
                Response::error('Registration failed. Please try again.');
            }
        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            Response::error('Registration failed: ' . $e->getMessage());
        }
    }

    public function login($data) {
        try {
            if (!Security::rateLimit('login_' . Security::getClientIP(), 5, 900)) {
                Response::error('Too many login attempts. Please try again in 15 minutes.', 429);
            }

            if (empty($data['email']) || empty($data['password'])) {
                Response::error('Email and password required');
            }

            $this->user->email = Security::sanitizeInput($data['email']);
            
            try {
                $user_exists = $this->user->emailExists();
            } catch (Exception $e) {
                Response::error($e->getMessage());
            }

            if (!$user_exists) {
                $this->user->updateLoginAttempts(false);
                Response::error('Invalid email or password');
            }

            if (!Security::verifyPassword($data['password'], $this->user->password_hash)) {
                $this->user->updateLoginAttempts(false);
                Response::error('Invalid email or password');
            }

            if ($this->user->status === 'suspended') {
                Response::error('Account suspended. Please contact support.');
            }

            // Check if 2FA is enabled
            if ($this->user->two_factor_enabled) {
                if (empty($data['two_factor_code'])) {
                    Response::success([
                        'requires_2fa' => true,
                        'user_id' => $this->user->id
                    ], 'Two-factor authentication required');
                } else {
                    if (!$this->user->verify2FA($this->user->id, $data['two_factor_code'])) {
                        Response::error('Invalid two-factor authentication code');
                    }
                }
            }

            $this->user->updateLoginAttempts(true);

            $token = Security::generateToken([
                'user_id' => $this->user->id,
                'email' => $this->user->email,
                'role' => $this->user->role
            ]);

            $this->logActivity($this->user->id, 'login', 'User logged in successfully');

            Response::success([
                'token' => $token,
                'user' => [
                    'id' => $this->user->id,
                    'full_name' => $this->user->full_name,
                    'email' => $this->user->email,
                    'role' => $this->user->role,
                    'referral_code' => $this->user->referral_code,
                    'balance' => $this->user->balance,
                    'kyc_verified' => $this->user->kyc_verified,
                    'two_factor_enabled' => $this->user->two_factor_enabled,
                    'risk_tolerance' => $this->user->risk_tolerance,
                    'investment_strategy' => $this->user->investment_strategy
                ]
            ], 'Login successful');
        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            Response::error('Login failed: ' . $e->getMessage());
        }
    }

    public function enable2FA($user_id) {
        try {
            $secret = $this->user->enable2FA($user_id);
            if ($secret) {
                $this->logActivity($user_id, '2fa_enabled', 'Two-factor authentication enabled');
                Response::success(['secret' => $secret], 'Two-factor authentication enabled successfully');
            } else {
                Response::error('Failed to enable two-factor authentication');
            }
        } catch (Exception $e) {
            error_log("2FA enable error: " . $e->getMessage());
            Response::error('Failed to enable two-factor authentication');
        }
    }

    public function disable2FA($user_id, $code) {
        try {
            if ($this->user->verify2FA($user_id, $code)) {
                if ($this->user->disable2FA($user_id)) {
                    $this->logActivity($user_id, '2fa_disabled', 'Two-factor authentication disabled');
                    Response::success(null, 'Two-factor authentication disabled successfully');
                } else {
                    Response::error('Failed to disable two-factor authentication');
                }
            } else {
                Response::error('Invalid verification code');
            }
        } catch (Exception $e) {
            error_log("2FA disable error: " . $e->getMessage());
            Response::error('Failed to disable two-factor authentication');
        }
    }

    public function getProfile($user_id) {
        try {
            $this->user->id = $user_id;
            if ($this->user->readOne()) {
                $dashboard_stats = $this->user->getDashboardStats($user_id);
                
                Response::success([
                    'user' => [
                        'id' => $this->user->id,
                        'full_name' => $this->user->full_name,
                        'email' => $this->user->email,
                        'phone' => $this->user->phone,
                        'balance' => $this->user->balance,
                        'total_invested' => $this->user->total_invested,
                        'total_earnings' => $this->user->total_earnings,
                        'referral_earnings' => $this->user->referral_earnings,
                        'referral_code' => $this->user->referral_code,
                        'referred_by' => $this->user->referred_by,
                        'kyc_verified' => $this->user->kyc_verified,
                        'status' => $this->user->status,
                        'two_factor_enabled' => $this->user->two_factor_enabled,
                        'risk_tolerance' => $this->user->risk_tolerance,
                        'investment_strategy' => $this->user->investment_strategy,
                        'created_at' => $this->user->created_at
                    ],
                    'dashboard_stats' => $dashboard_stats
                ]);
            } else {
                Response::error('User not found');
            }
        } catch (Exception $e) {
            error_log("Get profile error: " . $e->getMessage());
            Response::error('Failed to fetch profile');
        }
    }

    public function updateProfile($user_id, $data) {
        try {
            $this->user->id = $user_id;
            
            $errors = [];
            if (empty($data['full_name'])) {
                $errors['full_name'] = 'Full name is required';
            }
            if (empty($data['phone'])) {
                $errors['phone'] = 'Phone number is required';
            }

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            if ($this->user->updateProfile($data)) {
                $this->logActivity($user_id, 'profile_update', 'Profile updated successfully');
                Response::success(null, 'Profile updated successfully');
            } else {
                Response::error('Profile update failed');
            }
        } catch (Exception $e) {
            error_log("Update profile error: " . $e->getMessage());
            Response::error('Profile update failed');
        }
    }

    public function changePassword($user_id, $data) {
        try {
            if (empty($data['current_password']) || empty($data['new_password'])) {
                Response::error('Current password and new password are required');
            }

            $this->user->id = $user_id;
            $this->user->readOne();

            if (!Security::verifyPassword($data['current_password'], $this->user->password_hash)) {
                Response::error('Current password is incorrect');
            }

            if (strlen($data['new_password']) < 8) {
                Response::error('New password must be at least 8 characters');
            }

            $new_password_hash = Security::hashPassword($data['new_password']);
            $query = "UPDATE users SET password_hash = ? WHERE id = ?";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(1, $new_password_hash);
            $stmt->bindParam(2, $user_id);

            if ($stmt->execute()) {
                $this->logActivity($user_id, 'password_change', 'Password changed successfully');
                Response::success(null, 'Password changed successfully');
            } else {
                Response::error('Password change failed');
            }
        } catch (Exception $e) {
            error_log("Change password error: " . $e->getMessage());
            Response::error('Password change failed');
        }
    }

    private function logActivity($user_id, $action, $description) {
        $query = "INSERT INTO audit_logs 
                 SET user_id=:user_id, action=:action, description=:description,
                 ip_address=:ip_address, user_agent=:user_agent";
        
        $stmt = $this->db->prepare($query);
        $ip_address = Security::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        
        $stmt->execute();
    }
}

// Advanced Investment Controller with AI Recommendations
class InvestmentController {
    private $db;
    private $investment;

    public function __construct($db) {
        $this->db = $db;
        $this->investment = new Investment($db);
    }

    public function createInvestment($user_id, $data) {
        try {
            $errors = [];
            if (empty($data['plan_id'])) $errors['plan_id'] = 'Plan is required';
            if (empty($data['amount'])) $errors['amount'] = 'Amount is required';

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            $amount = floatval($data['amount']);
            if ($amount < 3500) {
                Response::error('Minimum investment amount is ₦3,500');
            }

            // Check user balance
            $user_stmt = $this->db->prepare("SELECT balance FROM users WHERE id = ?");
            $user_stmt->bindParam(1, $user_id);
            $user_stmt->execute();
            $user = $user_stmt->fetch(PDO::FETCH_ASSOC);

            if ($user['balance'] < $amount) {
                Response::error('Insufficient balance for investment');
            }

            // Get plan details
            $plan_stmt = $this->db->prepare("SELECT * FROM investment_plans WHERE id = ?");
            $plan_stmt->bindParam(1, $data['plan_id']);
            $plan_stmt->execute();
            $plan = $plan_stmt->fetch(PDO::FETCH_ASSOC);

            if (!$plan) {
                Response::error('Invalid investment plan');
            }

            $this->investment->user_id = $user_id;
            $this->investment->plan_id = intval($data['plan_id']);
            $this->investment->amount = $amount;
            $this->investment->daily_interest = floatval($plan['daily_interest']);
            $this->investment->total_interest = floatval($plan['total_interest']);
            $this->investment->duration = intval($plan['duration']);
            $this->investment->auto_renew = boolval($data['auto_renew'] ?? false);
            $this->investment->risk_level = $plan['risk_level'];

            $investment_id = $this->investment->create();

            if ($investment_id) {
                // Deduct amount from user balance
                $update_balance = $this->db->prepare("UPDATE users SET balance = balance - ? WHERE id = ?");
                $update_balance->bindParam(1, $amount);
                $update_balance->bindParam(2, $user_id);
                $update_balance->execute();

                // Process referral bonus for first investment
                $this->processReferralBonus($user_id, $amount);

                Response::success(['investment_id' => $investment_id], 'Investment created successfully and pending approval');
            } else {
                Response::error('Investment creation failed');
            }
        } catch (Exception $e) {
            error_log("Create investment error: " . $e->getMessage());
            Response::error('Investment creation failed: ' . $e->getMessage());
        }
    }

    public function getUserInvestments($user_id, $page = 1, $per_page = 10) {
        try {
            $offset = ($page - 1) * $per_page;
            $stmt = $this->investment->getUserInvestments($user_id, $per_page, $offset);
            $investments = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_stmt = $this->db->prepare("SELECT COUNT(*) as total FROM investments WHERE user_id = ?");
            $count_stmt->bindParam(1, $user_id);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($investments, $total, $page, $per_page, 'Investments fetched successfully');
        } catch (Exception $e) {
            error_log("Get investments error: " . $e->getMessage());
            Response::error('Failed to fetch investments');
        }
    }

    public function getInvestmentPlans() {
        try {
            $stmt = $this->db->prepare("SELECT * FROM investment_plans WHERE status = 'active' ORDER BY min_amount ASC");
            $stmt->execute();
            $plans = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['plans' => $plans], 'Investment plans fetched successfully');
        } catch (Exception $e) {
            error_log("Get plans error: " . $e->getMessage());
            Response::error('Failed to fetch investment plans');
        }
    }

    public function getInvestmentPerformance($user_id) {
        try {
            $performance = $this->investment->getInvestmentPerformance($user_id);
            Response::success(['performance' => $performance], 'Investment performance fetched successfully');
        } catch (Exception $e) {
            error_log("Get performance error: " . $e->getMessage());
            Response::error('Failed to fetch investment performance');
        }
    }

    public function getPortfolioAnalysis($user_id) {
        try {
            $analysis = $this->investment->getPortfolioAnalysis($user_id);
            Response::success(['analysis' => $analysis], 'Portfolio analysis fetched successfully');
        } catch (Exception $e) {
            error_log("Get portfolio analysis error: " . $e->getMessage());
            Response::error('Failed to fetch portfolio analysis');
        }
    }

    public function getRecommendations($user_id) {
        try {
            $recommendations = $this->investment->getInvestmentRecommendations($user_id);
            Response::success(['recommendations' => $recommendations], 'Investment recommendations fetched successfully');
        } catch (Exception $e) {
            error_log("Get recommendations error: " . $e->getMessage());
            Response::error('Failed to fetch investment recommendations');
        }
    }

    private function processReferralBonus($user_id, $investment_amount) {
        try {
            // Check if this is user's first investment
            $check_stmt = $this->db->prepare("SELECT COUNT(*) as investment_count FROM investments WHERE user_id = ?");
            $check_stmt->bindParam(1, $user_id);
            $check_stmt->execute();
            $result = $check_stmt->fetch(PDO::FETCH_ASSOC);

            if ($result['investment_count'] == 1) {
                // Get user's referral info
                $user_stmt = $this->db->prepare("SELECT referred_by FROM users WHERE id = ?");
                $user_stmt->bindParam(1, $user_id);
                $user_stmt->execute();
                $user = $user_stmt->fetch(PDO::FETCH_ASSOC);

                if ($user['referred_by']) {
                    // Calculate 20% bonus of first investment
                    $bonus_amount = $investment_amount * REFERRAL_BONUS_RATE;
                    
                    // Get referrer details
                    $referrer_stmt = $this->db->prepare("SELECT id, full_name FROM users WHERE referral_code = ?");
                    $referrer_stmt->bindParam(1, $user['referred_by']);
                    $referrer_stmt->execute();
                    $referrer = $referrer_stmt->fetch(PDO::FETCH_ASSOC);

                    if ($referrer) {
                        // Update referrer's balance
                        $update_stmt = $this->db->prepare("UPDATE users SET balance = balance + ?, referral_earnings = referral_earnings + ? WHERE id = ?");
                        $update_stmt->bindParam(1, $bonus_amount);
                        $update_stmt->bindParam(2, $bonus_amount);
                        $update_stmt->bindParam(3, $referrer['id']);
                        $update_stmt->execute();

                        // Create notification for referrer
                        $notif_stmt = $this->db->prepare("INSERT INTO notifications SET user_id = ?, title = '🎊 Referral Bonus!', message = ?, type = 'success', priority = 'high'");
                        $message = "You received ₦" . number_format($bonus_amount, 2) . " referral bonus from " . $user['full_name'] . "'s first investment!";
                        $notif_stmt->bindParam(1, $referrer['id']);
                        $notif_stmt->bindParam(2, $message);
                        $notif_stmt->execute();

                        // Log the referral bonus
                        $log_stmt = $this->db->prepare("INSERT INTO audit_logs SET user_id = ?, action = 'referral_bonus', description = ?");
                        $log_desc = "Received ₦" . number_format($bonus_amount, 2) . " referral bonus from user $user_id";
                        $log_stmt->bindParam(1, $referrer['id']);
                        $log_stmt->bindParam(2, $log_desc);
                        $log_stmt->execute();
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Referral bonus processing error: " . $e->getMessage());
        }
    }
}

// Advanced Deposit Controller with Multiple Payment Methods
class DepositController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function createDeposit($user_id, $data) {
        try {
            $errors = [];
            if (empty($data['amount'])) $errors['amount'] = 'Amount is required';
            if (empty($data['payment_method'])) $errors['payment_method'] = 'Payment method is required';
            if (empty($data['proof_image'])) $errors['proof_image'] = 'Payment proof is required';

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            $amount = floatval($data['amount']);
            if ($amount < MIN_DEPOSIT) {
                Response::error('Minimum deposit amount is ₦' . number_format(MIN_DEPOSIT, 2));
            }

            // Validate payment method
            $allowed_methods = ['bank_transfer', 'crypto', 'paypal', 'card', 'skrill', 'neteller'];
            if (!in_array($data['payment_method'], $allowed_methods)) {
                Response::error('Invalid payment method');
            }

            $query = "INSERT INTO deposit_requests 
                     SET user_id=:user_id, amount=:amount, payment_method=:payment_method,
                     proof_image=:proof_image, transaction_hash=:transaction_hash, currency=:currency";

            $stmt = $this->db->prepare($query);
            $currency = $data['currency'] ?? 'NGN';
            $transaction_hash = $data['transaction_hash'] ?? null;

            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":amount", $amount);
            $stmt->bindParam(":payment_method", $data['payment_method']);
            $stmt->bindParam(":proof_image", $data['proof_image']);
            $stmt->bindParam(":transaction_hash", $transaction_hash);
            $stmt->bindParam(":currency", $currency);

            if ($stmt->execute()) {
                $deposit_id = $this->db->lastInsertId();

                $this->createNotification(
                    $user_id,
                    "💰 Deposit Request Submitted",
                    "Your deposit request of ₦" . number_format($amount, 2) . " is under review. You will be notified once approved.",
                    'info'
                );

                Response::success(['deposit_id' => $deposit_id], 'Deposit request submitted successfully');
            } else {
                Response::error('Deposit request failed');
            }
        } catch (Exception $e) {
            error_log("Create deposit error: " . $e->getMessage());
            Response::error('Deposit request failed: ' . $e->getMessage());
        }
    }

    public function getUserDeposits($user_id, $page = 1, $per_page = 10) {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT * FROM deposit_requests 
                     WHERE user_id = :user_id 
                     ORDER BY created_at DESC 
                     LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $deposits = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_stmt = $this->db->prepare("SELECT COUNT(*) as total FROM deposit_requests WHERE user_id = ?");
            $count_stmt->bindParam(1, $user_id);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($deposits, $total, $page, $per_page, 'Deposits fetched successfully');
        } catch (Exception $e) {
            error_log("Get deposits error: " . $e->getMessage());
            Response::error('Failed to fetch deposits');
        }
    }

    public function getPaymentMethods() {
        $methods = [
            [
                'id' => 'bank_transfer',
                'name' => 'Bank Transfer',
                'description' => 'Direct bank transfer to Nigerian banks',
                'processing_time' => '1-3 business days',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 500000,
                'fees' => '0%'
            ],
            [
                'id' => 'crypto',
                'name' => 'Cryptocurrency',
                'description' => 'Bitcoin, Ethereum, USDT, BNB',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 1000000,
                'fees' => '0%'
            ],
            [
                'id' => 'paypal',
                'name' => 'PayPal',
                'description' => 'PayPal payment',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 200000,
                'fees' => '2.9%'
            ],
            [
                'id' => 'card',
                'name' => 'Credit/Debit Card',
                'description' => 'Visa, Mastercard, Verve',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 100000,
                'fees' => '3.5%'
            ]
        ];

        Response::success(['payment_methods' => $methods], 'Payment methods fetched successfully');
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications 
                 SET user_id=:user_id, title=:title, message=:message, type=:type, priority=:priority";
        
        $priority = 'medium';
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":type", $type);
        $stmt->bindParam(":priority", $priority);
        
        $stmt->execute();
    }
}

// Advanced Withdrawal Controller with Enhanced Security
class WithdrawalController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function createWithdrawal($user_id, $data) {
        try {
            $errors = [];
            if (empty($data['amount'])) $errors['amount'] = 'Amount is required';
            if (empty($data['payment_method'])) $errors['payment_method'] = 'Payment method is required';

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            $amount = floatval($data['amount']);
            $platform_fee = $amount * WITHDRAWAL_FEE_RATE;
            $net_amount = $amount - $platform_fee;

            if ($amount < MIN_WITHDRAWAL) {
                Response::error('Minimum withdrawal amount is ₦' . number_format(MIN_WITHDRAWAL, 2));
            }

            if ($amount > MAX_WITHDRAWAL) {
                Response::error('Maximum withdrawal amount is ₦' . number_format(MAX_WITHDRAWAL, 2));
            }

            // Check user balance
            $user_stmt = $this->db->prepare("SELECT balance, kyc_verified FROM users WHERE id = ?");
            $user_stmt->bindParam(1, $user_id);
            $user_stmt->execute();
            $user = $user_stmt->fetch(PDO::FETCH_ASSOC);

            if ($user['balance'] < $amount) {
                Response::error('Insufficient balance for withdrawal');
            }

            if (!$user['kyc_verified']) {
                Response::error('KYC verification required for withdrawals');
            }

            // Validate payment details based on method
            $validation_errors = $this->validatePaymentDetails($data);
            if (!empty($validation_errors)) {
                Response::validationError($validation_errors);
            }

            $this->db->beginTransaction();

            $query = "INSERT INTO withdrawal_requests 
                     SET user_id=:user_id, amount=:amount, platform_fee=:platform_fee,
                     net_amount=:net_amount, bank_name=:bank_name, account_name=:account_name,
                     account_number=:account_number, wallet_address=:wallet_address,
                     payment_method=:payment_method, swift_code=:swift_code, iban=:iban";

            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":amount", $amount);
            $stmt->bindParam(":platform_fee", $platform_fee);
            $stmt->bindParam(":net_amount", $net_amount);
            $stmt->bindParam(":bank_name", $data['bank_name']);
            $stmt->bindParam(":account_name", $data['account_name']);
            $stmt->bindParam(":account_number", $data['account_number']);
            $stmt->bindParam(":wallet_address", $data['wallet_address']);
            $stmt->bindParam(":payment_method", $data['payment_method']);
            $stmt->bindParam(":swift_code", $data['swift_code']);
            $stmt->bindParam(":iban", $data['iban']);

            if ($stmt->execute()) {
                $withdrawal_id = $this->db->lastInsertId();

                // Deduct from user balance immediately
                $update_balance = $this->db->prepare("UPDATE users SET balance = balance - ? WHERE id = ?");
                $update_balance->bindParam(1, $amount);
                $update_balance->bindParam(2, $user_id);
                $update_balance->execute();

                $this->createNotification(
                    $user_id,
                    "💸 Withdrawal Request Submitted",
                    "Your withdrawal request of ₦" . number_format($amount, 2) . " is under review. Net amount: ₦" . number_format($net_amount, 2),
                    'info'
                );

                $this->db->commit();

                Response::success(['withdrawal_id' => $withdrawal_id], 'Withdrawal request submitted successfully');
            } else {
                $this->db->rollBack();
                Response::error('Withdrawal request failed');
            }
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Create withdrawal error: " . $e->getMessage());
            Response::error('Withdrawal request failed: ' . $e->getMessage());
        }
    }

    public function getUserWithdrawals($user_id, $page = 1, $per_page = 10) {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT * FROM withdrawal_requests 
                     WHERE user_id = :user_id 
                     ORDER BY created_at DESC 
                     LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $withdrawals = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_stmt = $this->db->prepare("SELECT COUNT(*) as total FROM withdrawal_requests WHERE user_id = ?");
            $count_stmt->bindParam(1, $user_id);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($withdrawals, $total, $page, $per_page, 'Withdrawals fetched successfully');
        } catch (Exception $e) {
            error_log("Get withdrawals error: " . $e->getMessage());
            Response::error('Failed to fetch withdrawals');
        }
    }

    private function validatePaymentDetails($data) {
        $errors = [];
        $method = $data['payment_method'];

        switch ($method) {
            case 'bank_transfer':
                if (empty($data['bank_name'])) $errors['bank_name'] = 'Bank name is required';
                if (empty($data['account_name'])) $errors['account_name'] = 'Account name is required';
                if (empty($data['account_number'])) $errors['account_number'] = 'Account number is required';
                break;
            case 'crypto':
                if (empty($data['wallet_address'])) $errors['wallet_address'] = 'Wallet address is required';
                break;
            case 'paypal':
                if (empty($data['account_name'])) $errors['account_name'] = 'PayPal email is required';
                break;
        }

        return $errors;
    }

    private function createNotification($user_id, $title, $message, $type = 'info') {
        $query = "INSERT INTO notifications 
                 SET user_id=:user_id, title=:title, message=:message, type=:type, priority=:priority";
        
        $priority = 'medium';
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":type", $type);
        $stmt->bindParam(":priority", $priority);
        
        $stmt->execute();
    }
}

// Advanced Admin Controller with Comprehensive Management
class AdminController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function getDashboardStats() {
        try {
            $stats = [];

            // Total users
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_users FROM users WHERE role = 'user'");
            $stmt->execute();
            $stats['total_users'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_users'];

            // New users this month
            $stmt = $this->db->prepare("SELECT COUNT(*) as new_users_month FROM users WHERE role = 'user' AND MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())");
            $stmt->execute();
            $stats['new_users_month'] = $stmt->fetch(PDO::FETCH_ASSOC)['new_users_month'];

            // Total investments
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_investments, COALESCE(SUM(amount), 0) as total_invested FROM investments");
            $stmt->execute();
            $investment_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_investments'] = $investment_stats['total_investments'];
            $stats['total_invested'] = $investment_stats['total_invested'];

            // Active investments
            $stmt = $this->db->prepare("SELECT COUNT(*) as active_investments, COALESCE(SUM(amount), 0) as active_invested FROM investments WHERE status = 'active'");
            $stmt->execute();
            $active_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['active_investments'] = $active_stats['active_investments'];
            $stats['active_invested'] = $active_stats['active_invested'];

            // Total deposits
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_deposits, COALESCE(SUM(amount), 0) as total_deposited FROM deposit_requests WHERE status = 'approved'");
            $stmt->execute();
            $deposit_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_deposits'] = $deposit_stats['total_deposits'];
            $stats['total_deposited'] = $deposit_stats['total_deposited'];

            // Total withdrawals
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_withdrawals, COALESCE(SUM(amount), 0) as total_withdrawn FROM withdrawal_requests WHERE status = 'approved'");
            $stmt->execute();
            $withdrawal_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_withdrawals'] = $withdrawal_stats['total_withdrawals'];
            $stats['total_withdrawn'] = $withdrawal_stats['total_withdrawn'];

            // Total earnings (platform)
            $stmt = $this->db->prepare("SELECT COALESCE(SUM(platform_fee), 0) as total_earnings FROM withdrawal_requests WHERE status = 'approved'");
            $stmt->execute();
            $stats['total_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_earnings'];

            // Pending approvals
            $stmt = $this->db->prepare("SELECT 
                (SELECT COUNT(*) FROM deposit_requests WHERE status = 'pending') as pending_deposits,
                (SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'pending') as pending_withdrawals,
                (SELECT COUNT(*) FROM investments WHERE status = 'pending') as pending_investments");
            $stmt->execute();
            $pending_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['pending_approvals'] = $pending_stats['pending_deposits'] + $pending_stats['pending_withdrawals'] + $pending_stats['pending_investments'];
            $stats['pending_deposits'] = $pending_stats['pending_deposits'];
            $stats['pending_withdrawals'] = $pending_stats['pending_withdrawals'];
            $stats['pending_investments'] = $pending_stats['pending_investments'];

            // Recent activity
            $stmt = $this->db->prepare("SELECT action, COUNT(*) as count FROM audit_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY action");
            $stmt->execute();
            $stats['recent_activity'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['stats' => $stats], 'Dashboard statistics fetched successfully');
        } catch (Exception $e) {
            error_log("Get admin stats error: " . $e->getMessage());
            Response::error('Failed to fetch admin statistics');
        }
    }

    public function approveDeposit($admin_id, $deposit_id) {
        try {
            $this->db->beginTransaction();

            // Get deposit details
            $stmt = $this->db->prepare("SELECT * FROM deposit_requests WHERE id = ?");
            $stmt->bindParam(1, $deposit_id);
            $stmt->execute();
            $deposit = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$deposit) {
                Response::error('Deposit request not found');
            }

            if ($deposit['status'] !== 'pending') {
                Response::error('Deposit request already processed');
            }

            // Update deposit status
            $update_stmt = $this->db->prepare("UPDATE deposit_requests SET status = 'approved', processed_by = ?, processed_at = NOW() WHERE id = ?");
            $update_stmt->bindParam(1, $admin_id);
            $update_stmt->bindParam(2, $deposit_id);
            $update_stmt->execute();

            // Update user balance
            $user_stmt = $this->db->prepare("UPDATE users SET balance = balance + ? WHERE id = ?");
            $user_stmt->bindParam(1, $deposit['amount']);
            $user_stmt->bindParam(2, $deposit['user_id']);
            $user_stmt->execute();

            // Create transaction record
            $txn_stmt = $this->db->prepare("INSERT INTO transactions SET user_id = ?, type = 'deposit', amount = ?, status = 'completed', description = 'Deposit approved'");
            $txn_stmt->bindParam(1, $deposit['user_id']);
            $txn_stmt->bindParam(2, $deposit['amount']);
            $txn_stmt->execute();

            // Create notification
            $notif_stmt = $this->db->prepare("INSERT INTO notifications SET user_id = ?, title = '💰 Deposit Approved', message = ?, type = 'success', priority = 'high'");
            $message = "Your deposit of ₦" . number_format($deposit['amount'], 2) . " has been approved and added to your balance.";
            $notif_stmt->bindParam(1, $deposit['user_id']);
            $notif_stmt->bindParam(2, $message);
            $notif_stmt->execute();

            $this->db->commit();

            Response::success(null, 'Deposit approved successfully');
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Approve deposit error: " . $e->getMessage());
            Response::error('Failed to approve deposit');
        }
    }

    public function approveWithdrawal($admin_id, $withdrawal_id) {
        try {
            $this->db->beginTransaction();

            // Get withdrawal details
            $stmt = $this->db->prepare("SELECT * FROM withdrawal_requests WHERE id = ?");
            $stmt->bindParam(1, $withdrawal_id);
            $stmt->execute();
            $withdrawal = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$withdrawal) {
                Response::error('Withdrawal request not found');
            }

            if ($withdrawal['status'] !== 'pending') {
                Response::error('Withdrawal request already processed');
            }

            // Update withdrawal status
            $update_stmt = $this->db->prepare("UPDATE withdrawal_requests SET status = 'approved', processed_by = ?, processed_at = NOW() WHERE id = ?");
            $update_stmt->bindParam(1, $admin_id);
            $update_stmt->bindParam(2, $withdrawal_id);
            $update_stmt->execute();

            // Create transaction record
            $txn_stmt = $this->db->prepare("INSERT INTO transactions SET user_id = ?, type = 'withdrawal', amount = ?, status = 'completed', description = 'Withdrawal approved'");
            $txn_stmt->bindParam(1, $withdrawal['user_id']);
            $txn_stmt->bindParam(2, $withdrawal['amount']);
            $txn_stmt->execute();

            // Create notification
            $notif_stmt = $this->db->prepare("INSERT INTO notifications SET user_id = ?, title = '💸 Withdrawal Approved', message = ?, type = 'success', priority = 'high'");
            $message = "Your withdrawal of ₦" . number_format($withdrawal['amount'], 2) . " has been approved and will be processed shortly.";
            $notif_stmt->bindParam(1, $withdrawal['user_id']);
            $notif_stmt->bindParam(2, $message);
            $notif_stmt->execute();

            $this->db->commit();

            Response::success(null, 'Withdrawal approved successfully');
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Approve withdrawal error: " . $e->getMessage());
            Response::error('Failed to approve withdrawal');
        }
    }

    public function approveInvestment($admin_id, $investment_id) {
        try {
            $investment = new Investment($this->db);
            
            if ($investment->updateStatus($investment_id, 'active', $admin_id)) {
                Response::success(null, 'Investment approved successfully');
            } else {
                Response::error('Failed to approve investment');
            }
        } catch (Exception $e) {
            error_log("Approve investment error: " . $e->getMessage());
            Response::error('Failed to approve investment');
        }
    }

    public function getUsers($page = 1, $per_page = 20, $search = '') {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT id, full_name, email, phone, balance, total_invested, total_earnings, 
                             referral_earnings, referral_code, status, kyc_verified, created_at 
                     FROM users 
                     WHERE role = 'user'";
            
            if (!empty($search)) {
                $query .= " AND (full_name LIKE :search OR email LIKE :search OR phone LIKE :search)";
            }
            
            $query .= " ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            
            if (!empty($search)) {
                $search_term = "%$search%";
                $stmt->bindParam(":search", $search_term);
            }
            
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get total count
            $count_query = "SELECT COUNT(*) as total FROM users WHERE role = 'user'";
            if (!empty($search)) {
                $count_query .= " AND (full_name LIKE :search OR email LIKE :search OR phone LIKE :search)";
            }
            
            $count_stmt = $this->db->prepare($count_query);
            if (!empty($search)) {
                $count_stmt->bindParam(":search", $search_term);
            }
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($users, $total, $page, $per_page, 'Users fetched successfully');
        } catch (Exception $e) {
            error_log("Get users error: " . $e->getMessage());
            Response::error('Failed to fetch users');
        }
    }

    public function updateUserStatus($user_id, $status) {
        try {
            $allowed_statuses = ['active', 'suspended', 'pending'];
            if (!in_array($status, $allowed_statuses)) {
                Response::error('Invalid status');
            }

            $stmt = $this->db->prepare("UPDATE users SET status = ? WHERE id = ?");
            $stmt->bindParam(1, $status);
            $stmt->bindParam(2, $user_id);

            if ($stmt->execute()) {
                Response::success(null, 'User status updated successfully');
            } else {
                Response::error('Failed to update user status');
            }
        } catch (Exception $e) {
            error_log("Update user status error: " . $e->getMessage());
            Response::error('Failed to update user status');
        }
    }
}

// Advanced Application Router with Enhanced Routing
class Application {
    private $db;
    private $authController;
    private $investmentController;
    private $depositController;
    private $withdrawalController;
    private $adminController;

    public function __construct() {
        $database = new Database();
        $this->db = $database->getConnection();
        
        $this->authController = new AuthController($this->db);
        $this->investmentController = new InvestmentController($this->db);
        $this->depositController = new DepositController($this->db);
        $this->withdrawalController = new WithdrawalController($this->db);
        $this->adminController = new AdminController($this->db);
    }

    public function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $path = str_replace('/index.php', '', $path);
        
        // Handle preflight requests
        if ($method === 'OPTIONS') {
            Response::success([]);
        }

        try {
            switch ($path) {
                case '/api/register':
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->authController->register($data);
                    }
                    break;

                case '/api/login':
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->authController->login($data);
                    }
                    break;

                case '/api/profile':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->authController->getProfile($user['user_id']);
                    } elseif ($method === 'PUT') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->authController->updateProfile($user['user_id'], $data);
                    }
                    break;

                case '/api/profile/password':
                    $user = $this->authenticate();
                    if ($method === 'PUT') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->authController->changePassword($user['user_id'], $data);
                    }
                    break;

                case '/api/2fa/enable':
                    $user = $this->authenticate();
                    if ($method === 'POST') {
                        $this->authController->enable2FA($user['user_id']);
                    }
                    break;

                case '/api/2fa/disable':
                    $user = $this->authenticate();
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->authController->disable2FA($user['user_id'], $data['code']);
                    }
                    break;

                case '/api/investments':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->investmentController->getUserInvestments($user['user_id'], $page);
                    } elseif ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->investmentController->createInvestment($user['user_id'], $data);
                    }
                    break;

                case '/api/investment-plans':
                    if ($method === 'GET') {
                        $this->investmentController->getInvestmentPlans();
                    }
                    break;

                case '/api/investment-performance':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->investmentController->getInvestmentPerformance($user['user_id']);
                    }
                    break;

                case '/api/portfolio-analysis':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->investmentController->getPortfolioAnalysis($user['user_id']);
                    }
                    break;

                case '/api/investment-recommendations':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->investmentController->getRecommendations($user['user_id']);
                    }
                    break;

                case '/api/deposits':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->depositController->getUserDeposits($user['user_id'], $page);
                    } elseif ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->depositController->createDeposit($user['user_id'], $data);
                    }
                    break;

                case '/api/payment-methods':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->depositController->getPaymentMethods();
                    }
                    break;

                case '/api/withdrawals':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->withdrawalController->getUserWithdrawals($user['user_id'], $page);
                    } elseif ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->withdrawalController->createWithdrawal($user['user_id'], $data);
                    }
                    break;

                case '/api/admin/dashboard':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->adminController->getDashboardStats();
                    }
                    break;

                case '/api/admin/approve-deposit':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->adminController->approveDeposit($user['user_id'], $data['deposit_id']);
                    }
                    break;

                case '/api/admin/approve-withdrawal':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->adminController->approveWithdrawal($user['user_id'], $data['withdrawal_id']);
                    }
                    break;

                case '/api/admin/approve-investment':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->adminController->approveInvestment($user['user_id'], $data['investment_id']);
                    }
                    break;

                case '/api/admin/users':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $search = $_GET['search'] ?? '';
                        $this->adminController->getUsers($page, 20, $search);
                    }
                    break;

                case '/api/admin/users/status':
                    $user = $this->authenticateAdmin();
                    if ($method === 'PUT') {
                        $data = json_decode(file_get_contents('php://input'), true);
                        $this->adminController->updateUserStatus($data['user_id'], $data['status']);
                    }
                    break;

                case '/api/cron/daily-earnings':
                    if ($method === 'POST' && $this->validateCronSecret()) {
                        $investment = new Investment($this->db);
                        $earnings_created = $investment->calculateDailyEarnings();
                        $completed_investments = $investment->checkCompletion();
                        Response::success([
                            'earnings_created' => $earnings_created,
                            'completed_investments' => $completed_investments
                        ], 'Daily earnings processed successfully');
                    } else {
                        Response::error('Unauthorized', 401);
                    }
                    break;

                case '/api/health':
                    if ($method === 'GET') {
                        Response::success([
                            'status' => 'healthy',
                            'timestamp' => time(),
                            'version' => APP_VERSION,
                            'database' => 'connected'
                        ], 'System is healthy');
                    }
                    break;

                default:
                    Response::error('Endpoint not found', 404);
            }
        } catch (Exception $e) {
            error_log("Application error: " . $e->getMessage());
            Response::error('Internal server error', 500);
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

        if ($user['role'] !== 'admin') {
            Response::error('Admin access required', 403);
        }

        return $user;
    }

    private function validateCronSecret() {
        $headers = getallheaders();
        $cron_secret = $headers['X-Cron-Secret'] ?? '';
        return $cron_secret === 'raw-wealthy-cron-secret-2024';
    }
}

// Advanced Database Initialization and Setup
function initializeDatabase($db) {
    try {
        // Create tables if they don't exist
        $tables_sql = [
            "CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20),
                password_hash VARCHAR(255) NOT NULL,
                balance DECIMAL(15,2) DEFAULT 0.00,
                total_invested DECIMAL(15,2) DEFAULT 0.00,
                total_earnings DECIMAL(15,2) DEFAULT 0.00,
                referral_earnings DECIMAL(15,2) DEFAULT 0.00,
                referral_code VARCHAR(20) UNIQUE,
                referred_by VARCHAR(20),
                role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
                kyc_verified BOOLEAN DEFAULT FALSE,
                status ENUM('active', 'suspended', 'pending') DEFAULT 'active',
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                two_factor_secret VARCHAR(100),
                risk_tolerance ENUM('low', 'medium', 'high') DEFAULT 'medium',
                investment_strategy ENUM('conservative', 'balanced', 'aggressive') DEFAULT 'balanced',
                last_login TIMESTAMP NULL,
                login_attempts INT DEFAULT 0,
                locked_until TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_referral_code (referral_code),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS investment_plans (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                min_amount DECIMAL(15,2) NOT NULL,
                max_amount DECIMAL(15,2) NULL,
                daily_interest DECIMAL(5,2) NOT NULL,
                total_interest DECIMAL(5,2) NOT NULL,
                duration INT NOT NULL,
                description TEXT,
                risk_level ENUM('low', 'medium', 'high') DEFAULT 'medium',
                status ENUM('active', 'inactive', 'coming_soon') DEFAULT 'active',
                features JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_status (status),
                INDEX idx_risk_level (risk_level)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS investments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                plan_id INT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                daily_interest DECIMAL(5,2) NOT NULL,
                total_interest DECIMAL(5,2) NOT NULL,
                duration INT NOT NULL,
                start_date TIMESTAMP NULL,
                end_date TIMESTAMP NULL,
                status ENUM('pending', 'active', 'completed', 'rejected', 'paused') DEFAULT 'pending',
                proof_image VARCHAR(255),
                earnings_paid DECIMAL(15,2) DEFAULT 0.00,
                expected_earnings DECIMAL(15,2) DEFAULT 0.00,
                auto_renew BOOLEAN DEFAULT FALSE,
                risk_level ENUM('low', 'medium', 'high') DEFAULT 'medium',
                profitability_score DECIMAL(5,2) DEFAULT 0.00,
                market_trend ENUM('bullish', 'stable', 'volatile', 'bearish') DEFAULT 'stable',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (plan_id) REFERENCES investment_plans(id),
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at),
                INDEX idx_end_date (end_date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS transactions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                type ENUM('investment', 'deposit', 'withdrawal', 'earning', 'referral', 'bonus', 'penalty', 'fee') NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                description TEXT,
                status ENUM('pending', 'completed', 'rejected', 'cancelled') DEFAULT 'pending',
                reference VARCHAR(100) UNIQUE,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_type (type),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS deposit_requests (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                payment_method ENUM('bank_transfer', 'crypto', 'paypal', 'card', 'skrill', 'neteller') DEFAULT 'bank_transfer',
                proof_image VARCHAR(255),
                transaction_hash VARCHAR(255),
                currency VARCHAR(10) DEFAULT 'NGN',
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                admin_notes TEXT,
                processed_by INT NULL,
                processed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                platform_fee DECIMAL(15,2) NOT NULL,
                net_amount DECIMAL(15,2) NOT NULL,
                bank_name VARCHAR(255),
                account_name VARCHAR(255),
                account_number VARCHAR(255),
                wallet_address VARCHAR(255),
                payment_method ENUM('bank_transfer', 'crypto', 'paypal', 'skrill') DEFAULT 'bank_transfer',
                swift_code VARCHAR(20),
                iban VARCHAR(50),
                status ENUM('pending', 'approved', 'rejected', 'processing') DEFAULT 'pending',
                admin_notes TEXT,
                processed_by INT NULL,
                processed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS daily_earnings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                investment_id INT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                base_amount DECIMAL(15,2) NOT NULL,
                risk_adjustment DECIMAL(5,2) DEFAULT 1.00,
                market_adjustment DECIMAL(5,2) DEFAULT 1.00,
                earning_date DATE NOT NULL,
                paid BOOLEAN DEFAULT FALSE,
                paid_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (investment_id) REFERENCES investments(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_investment_id (investment_id),
                INDEX idx_earning_date (earning_date),
                UNIQUE KEY unique_earning (investment_id, earning_date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS notifications (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                type ENUM('info', 'success', 'warning', 'error') DEFAULT 'info',
                priority ENUM('low', 'medium', 'high') DEFAULT 'medium',
                is_read BOOLEAN DEFAULT FALSE,
                action_url VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_is_read (is_read),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NULL,
                action VARCHAR(100) NOT NULL,
                description TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_action (action),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];

        foreach ($tables_sql as $sql) {
            $db->exec($sql);
        }

        // Insert default admin user if not exists
        $check_admin = $db->prepare("SELECT id FROM users WHERE email = 'admin@rawwealthy.com'");
        $check_admin->execute();
        
        if ($check_admin->rowCount() == 0) {
            $admin_password = Security::hashPassword('Admin123!');
            $insert_admin = $db->prepare("INSERT INTO users (full_name, email, password_hash, role, referral_code, kyc_verified, balance, risk_tolerance) VALUES ('Admin User', 'admin@rawwealthy.com', ?, 'admin', 'ADMIN001', TRUE, 1000000.00, 'medium')");
            $insert_admin->execute([$admin_password]);
        }

        // Insert 25 investment plans in Naira
        $check_plans = $db->prepare("SELECT id FROM investment_plans");
        $check_plans->execute();
        
        if ($check_plans->rowCount() == 0) {
            $plans_sql = "INSERT INTO investment_plans (name, min_amount, max_amount, daily_interest, total_interest, duration, description, risk_level, features) VALUES 
                ('Starter Plan', 3500, 10000, 2.5, 75, 30, 'Perfect for beginners with low risk tolerance. Start your investment journey with confidence.', 'low', '[\"Low Risk\", \"Beginner Friendly\", \"Daily Payouts\", \"24/7 Support\"]'),
                ('Silver Growth', 5000, 25000, 3.0, 90, 30, 'Balanced growth with moderate risk. Ideal for steady portfolio expansion.', 'medium', '[\"Balanced Growth\", \"Moderate Risk\", \"Stable Returns\", \"Portfolio Diversification\"]'),
                ('Gold Premium', 10000, 50000, 3.5, 105, 30, 'Premium investment with higher returns. For experienced investors seeking growth.', 'medium', '[\"Premium Returns\", \"Experienced Level\", \"Growth Focus\", \"Priority Support\"]'),
                ('Platinum Elite', 25000, 100000, 4.0, 120, 30, 'Elite investment plan with exceptional returns and premium features.', 'high', '[\"Elite Returns\", \"Premium Features\", \"VIP Support\", \"Exclusive Opportunities\"]'),
                ('Diamond Wealth', 50000, 200000, 4.5, 135, 30, 'Maximum returns for serious investors. High risk, high reward strategy.', 'high', '[\"Maximum Returns\", \"High Reward\", \"Wealth Building\", \"Exclusive Access\"]'),
                ('Naira Accelerator', 75000, 300000, 5.0, 150, 30, 'Accelerated growth plan for substantial capital appreciation.', 'high', '[\"Accelerated Growth\", \"Capital Appreciation\", \"Advanced Strategy\", \"Market Leadership\"]'),
                ('Wealth Builder', 100000, 400000, 5.5, 165, 30, 'Build substantial wealth through strategic investments and compounding.', 'high', '[\"Wealth Building\", \"Strategic Investment\", \"Compounding\", \"Long-term Growth\"]'),
                ('Fortune Maker', 150000, 500000, 6.0, 180, 30, 'Create fortunes through high-yield investments and market opportunities.', 'high', '[\"Fortune Creation\", \"High Yield\", \"Market Opportunities\", \"Exclusive Deals\"]'),
                ('Business Pro', 200000, 500000, 6.5, 195, 30, 'Professional investment plan for business-minded individuals.', 'high', '[\"Professional Grade\", \"Business Focus\", \"Strategic Planning\", \"Corporate Level\"]'),
                ('Enterprise Gold', 250000, 500000, 7.0, 210, 30, 'Enterprise-level investment with institutional-grade returns.', 'high', '[\"Enterprise Level\", \"Institutional Grade\", \"Maximum Security\", \"Dedicated Manager\"]'),
                ('Quick Return', 3500, 15000, 2.8, 84, 30, 'Quick returns with minimal risk. Perfect for short-term investors.', 'low', '[\"Quick Returns\", \"Short-term\", \"Minimal Risk\", \"Flexible Terms\"]'),
                ('Steady Income', 7000, 35000, 3.2, 96, 30, 'Consistent income generation with reliable daily payouts.', 'medium', '[\"Steady Income\", \"Reliable Payouts\", \"Consistent Returns\", \"Income Focus\"]'),
                ('Growth Plus', 15000, 75000, 3.8, 114, 30, 'Enhanced growth potential with balanced risk management.', 'medium', '[\"Enhanced Growth\", \"Balanced Risk\", \"Growth Focus\", \"Risk Management\"]'),
                ('Premium Plus', 30000, 150000, 4.2, 126, 30, 'Premium features with enhanced returns and additional benefits.', 'high', '[\"Premium Features\", \"Enhanced Returns\", \"Additional Benefits\", \"VIP Treatment\"]'),
                ('Ultimate Wealth', 60000, 300000, 4.8, 144, 30, 'Ultimate wealth creation strategy with maximum potential.', 'high', '[\"Ultimate Wealth\", \"Maximum Potential\", \"Wealth Creation\", \"Exclusive Strategy\"]'),
                ('Naira Master', 120000, 500000, 5.2, 156, 30, 'Master-level investment strategy for serious wealth accumulation.', 'high', '[\"Master Level\", \"Wealth Accumulation\", \"Advanced Techniques\", \"Expert Guidance\"]'),
                ('Capital King', 180000, 500000, 5.8, 174, 30, 'King-sized returns with royal treatment and premium support.', 'high', '[\"King-sized Returns\", \"Royal Treatment\", \"Premium Support\", \"Exclusive Access\"]'),
                ('Wealth Titan', 220000, 500000, 6.2, 186, 30, 'Titan-level investment power for massive wealth creation.', 'high', '[\"Titan Level\", \"Massive Wealth\", \"Power Investing\", \"Maximum Impact\"]'),
                ('Future Fortune', 280000, 500000, 6.8, 204, 30, 'Build your future fortune with strategic long-term planning.', 'high', '[\"Future Fortune\", \"Long-term Planning\", \"Strategic Vision\", \"Legacy Building\"]'),
                ('Legacy Builder', 350000, 500000, 7.2, 216, 30, 'Create a lasting legacy through intelligent wealth building.', 'high', '[\"Legacy Building\", \"Intelligent Wealth\", \"Lasting Impact\", \"Generational Wealth\"]'),
                ('Naira Champion', 400000, 500000, 7.5, 225, 30, 'Champion-level returns with unbeatable investment performance.', 'high', '[\"Champion Level\", \"Unbeatable Performance\", \"Top Returns\", \"Elite Status\"]'),
                ('Wealth Warrior', 450000, 500000, 7.8, 234, 30, 'Fight for your financial freedom with warrior-level determination.', 'high', '[\"Wealth Warrior\", \"Financial Freedom\", \"Determination\", \"Victory Mindset\"]'),
                ('Millionaire Blueprint', 480000, 500000, 8.0, 240, 30, 'The blueprint to millionaire status through smart investments.', 'high', '[\"Millionaire Blueprint\", \"Smart Investments\", \"Wealth Formula\", \"Success Path\"]'),
                ('Empire Builder', 490000, 500000, 8.2, 246, 30, 'Build your financial empire with empire-level investment strategy.', 'high', '[\"Empire Builder\", \"Financial Empire\", \"Strategic Mastery\", \"Dominant Returns\"]'),
                ('Raw Wealth Ultimate', 500000, 500000, 8.5, 255, 30, 'The ultimate investment plan for maximum wealth creation and financial freedom.', 'high', '[\"Ultimate Plan\", \"Maximum Wealth\", \"Financial Freedom\", \"Peak Performance\"]')";
            
            $db->exec($plans_sql);
        }

        return true;
    } catch (Exception $e) {
        error_log("Database initialization error: " . $e->getMessage());
        return false;
    }
}

// Initialize and run the application
try {
    // Create logs directory if it doesn't exist
    if (!is_dir(__DIR__ . '/logs')) {
        mkdir(__DIR__ . '/logs', 0755, true);
    }
    
    // Create uploads directory if it doesn't exist
    if (!is_dir(UPLOAD_PATH)) {
        mkdir(UPLOAD_PATH, 0755, true);
    }

    $database = new Database();
    $db = $database->getConnection();
    
    // Initialize database tables
    if (initializeDatabase($db)) {
        $app = new Application();
        $app->handleRequest();
    } else {
        throw new Exception("Database initialization failed");
    }
} catch (Exception $e) {
    error_log("Application startup failed: " . $e->getMessage());
    Response::error('Application startup failed. Please try again later.', 500);
}

?>

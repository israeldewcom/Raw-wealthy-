<?php
/* 
 * Raw Wealthy Investment Platform - Enterprise Production Edition v5.0
 * Advanced Platform with Complete Feature Set in Single File
 * Enhanced Security, Performance, Scalability, and Profitability Features
 * Market-Ready with Advanced Investment Algorithms
 * FULLY INTEGRATED FRONTEND-BACKEND COMMUNICATION
 * 25 Investment Plans with $3,500 - $300,000 Range
 * 10% Withdrawal Fees & 10% Referral Commissions
 * Advanced Admin Dashboard
 */

// Strict error reporting for production
error_reporting(E_ALL);
ini_set('display_errors', 0);
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
define('APP_VERSION', '5.0.0');
define('BASE_URL', 'https://' . $_SERVER['HTTP_HOST'] . '/');
define('UPLOAD_PATH', realpath(dirname(__FILE__) . '/uploads') . '/');
define('MAX_FILE_SIZE', 50 * 1024 * 1024);
define('JWT_SECRET', getenv('JWT_SECRET') ?: 'raw-wealthy-enterprise-secure-key-2024-change-in-production');
define('JWT_EXPIRY', 86400);
define('REFERRAL_BONUS_RATE', 0.10); // Changed to 10%
define('WITHDRAWAL_FEE_RATE', 0.10); // Changed to 10%
define('MIN_DEPOSIT', 500);
define('MIN_WITHDRAWAL', 1000);
define('MAX_WITHDRAWAL', 300000);
define('DAILY_PROFIT_RATE', 0.045);
define('COMPOUND_INTEREST_RATE', 0.025);
define('RISK_MANAGEMENT_BUFFER', 0.12);

// Enhanced CORS Configuration
$allowed_origins = [
    'https://rawwealthy.com',
    'https://www.rawwealthy.com',
    'https://app.rawwealthy.com',
    'https://admin.rawwealthy.com',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: https://rawwealthy.com");
}

// Advanced security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// CORS headers for modern applications
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-API-Key, X-CSRF-Token, X-Cron-Secret");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Max-Age: 86400");

// Enterprise Database Configuration
class Database {
    private $host = 'localhost';
    private $db_name = 'raw_wealthy_enterprise_v5';
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
    private static $encryption_key = 'raw-wealthy-32-char-encryption-key-2024';
    private static $cipher = "AES-256-CBC";
    
    public static function generateToken($payload) {
        $header = ['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'rawwealthy2024'];
        $payload['iss'] = BASE_URL;
        $payload['aud'] = BASE_URL;
        $payload['iat'] = time();
        $payload['exp'] = time() + JWT_EXPIRY;
        $payload['jti'] = bin2hex(random_bytes(16));
        $payload['nbf'] = time() - 60;

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
        
        if ($rate_data['blocked_until'] && $now < $rate_data['blocked_until']) {
            return false;
        }
        
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
        
        if ($file['size'] > MAX_FILE_SIZE) {
            $errors[] = "File size exceeds maximum allowed size of " . (MAX_FILE_SIZE / 1024 / 1024) . "MB";
        }
        
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errors[] = "File upload error: " . $file['error'];
        }
        
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
        
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'doc', 'docx'];
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($file_extension, $allowed_extensions)) {
            $errors[] = "File extension not allowed";
        }
        
        if (strpos($mime_type, 'image/') === 0) {
            $image_info = getimagesize($file['tmp_name']);
            if ($image_info === false) {
                $errors[] = "Invalid image file";
            }
        }
        
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

// Advanced File Upload Handler with Enhanced Security
class FileUploader {
    private $allowed_types = [
        'image/jpeg', 'image/png', 'image/jpg', 'image/gif', 'image/webp',
        'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    
    private $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'doc', 'docx'];
    
    public function handleUpload($file, $upload_type = 'general') {
        try {
            // Validate upload
            $errors = Security::validateFileUpload($file);
            if (!empty($errors)) {
                throw new Exception(implode(', ', $errors));
            }
            
            // Create upload directory if it doesn't exist
            if (!is_dir(UPLOAD_PATH)) {
                mkdir(UPLOAD_PATH, 0755, true);
            }
            
            // Generate secure filename
            $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $secure_filename = $this->generateSecureFilename($file_extension, $upload_type);
            $target_path = UPLOAD_PATH . $secure_filename;
            
            // Move uploaded file
            if (!move_uploaded_file($file['tmp_name'], $target_path)) {
                throw new Exception('Failed to move uploaded file');
            }
            
            // Validate image integrity for images
            if (strpos($file['type'], 'image/') === 0) {
                $this->validateImageIntegrity($target_path);
            }
            
            return [
                'success' => true,
                'filename' => $secure_filename,
                'original_name' => $file['name'],
                'file_path' => $target_path,
                'file_size' => $file['size'],
                'file_type' => $file['type']
            ];
            
        } catch (Exception $e) {
            error_log("File upload error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function generateSecureFilename($extension, $type) {
        $timestamp = time();
        $random_string = bin2hex(random_bytes(8));
        return "{$type}_{$timestamp}_{$random_string}.{$extension}";
    }
    
    private function validateImageIntegrity($file_path) {
        $image_info = getimagesize($file_path);
        if ($image_info === false) {
            unlink($file_path);
            throw new Exception('Invalid image file after upload');
        }
        
        // Check for potential PHP injection in images
        $file_content = file_get_contents($file_path);
        if (preg_match('/<\?php|<\?=|script/i', $file_content)) {
            unlink($file_path);
            throw new Exception('Image contains potentially dangerous content');
        }
    }
    
    public function deleteFile($filename) {
        $file_path = UPLOAD_PATH . $filename;
        if (file_exists($file_path)) {
            return unlink($file_path);
        }
        return false;
    }
}

// Advanced Response Handler with Caching Support
class Response {
    private static $cache_enabled = true;
    private static $cache_time = 300;

    public static function send($data, $status = 200, $cache_key = null) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        
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

            $initial_balance = 100.00;
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
                
                if ($this->referred_by) {
                    $this->processReferralBonus($this->referred_by, $this->id);
                }

                $this->createNotification(
                    $this->id,
                    "🎉 Welcome to Raw Wealthy!",
                    "Thank you for registering! You've received a $100 welcome bonus. Start your investment journey today!",
                    'success'
                );

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
        
        $query = "SELECT COUNT(*) as active_investments, COALESCE(SUM(amount), 0) as active_investment_value 
                 FROM investments 
                 WHERE user_id = ? AND status = 'active'";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $investment_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['active_investments'] = $investment_stats['active_investments'];
        $stats['active_investment_value'] = $investment_stats['active_investment_value'];

        $query = "SELECT COUNT(*) as total_referrals FROM users 
                 WHERE referred_by = (SELECT referral_code FROM users WHERE id = ?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['total_referrals'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_referrals'];

        $query = "SELECT COALESCE(SUM(amount), 0) as today_earnings FROM daily_earnings 
                 WHERE user_id = ? AND earning_date = CURDATE()";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['today_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['today_earnings'];

        $query = "SELECT COALESCE(SUM(amount), 0) as pending_withdrawals FROM withdrawal_requests 
                 WHERE user_id = ? AND status = 'pending'";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['pending_withdrawals'] = $stmt->fetch(PDO::FETCH_ASSOC)['pending_withdrawals'];

        $query = "SELECT COALESCE(SUM(amount), 0) as weekly_earnings FROM daily_earnings 
                 WHERE user_id = ? AND earning_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $stats['weekly_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['weekly_earnings'];

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

    public function getReferralStats($user_id) {
        $stats = [];
        
        $query = "SELECT COUNT(*) as total_referrals, 
                         SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_referrals,
                         SUM(CASE WHEN kyc_verified = 1 THEN 1 ELSE 0 END) as verified_referrals
                 FROM users 
                 WHERE referred_by = (SELECT referral_code FROM users WHERE id = ?)";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $referral_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $stats['total_referrals'] = $referral_stats['total_referrals'];
        $stats['active_referrals'] = $referral_stats['active_referrals'];
        $stats['verified_referrals'] = $referral_stats['verified_referrals'];
        $stats['referral_earnings'] = $this->getReferralEarnings($user_id);
        $stats['pending_earnings'] = $this->getPendingReferralEarnings($user_id);
        
        return $stats;
    }

    private function getReferralEarnings($user_id) {
        $query = "SELECT COALESCE(SUM(amount), 0) as total_earnings 
                 FROM referral_earnings 
                 WHERE referrer_id = ? AND status = 'paid'";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        
        return $stmt->fetch(PDO::FETCH_ASSOC)['total_earnings'];
    }

    private function getPendingReferralEarnings($user_id) {
        $query = "SELECT COALESCE(SUM(amount), 0) as pending_earnings 
                 FROM referral_earnings 
                 WHERE referrer_id = ? AND status = 'pending'";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        
        return $stmt->fetch(PDO::FETCH_ASSOC)['pending_earnings'];
    }

    private function processReferralBonus($referral_code, $new_user_id) {
        $referrer = $this->getByReferralCode($referral_code);
        if ($referrer) {
            $bonus_amount = 50.00;
            
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
                    "You've received a $50 bonus for referring " . $this->full_name . "!",
                    'success'
                );
                
                $this->logActivity($referrer['id'], 'referral_bonus', "Received referral bonus for user $new_user_id");
            }
        }
    }

    public function processInvestmentReferralBonus($referrer_id, $investment_amount) {
        $bonus_amount = $investment_amount * REFERRAL_BONUS_RATE;
        
        $query = "UPDATE " . $this->table_name . " 
                 SET referral_earnings = referral_earnings + ?, balance = balance + ?
                 WHERE id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $bonus_amount);
        $stmt->bindParam(2, $bonus_amount);
        $stmt->bindParam(3, $referrer_id);
        
        if ($stmt->execute()) {
            $this->createNotification(
                $referrer_id,
                "💰 Investment Referral Bonus!",
                "You've received a $" . number_format($bonus_amount, 2) . " bonus from your referral's investment!",
                'success'
            );
            
            $this->logActivity($referrer_id, 'investment_referral_bonus', "Received investment referral bonus: $" . $bonus_amount);
            return true;
        }
        return false;
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
                
                $user_update = $this->conn->prepare("UPDATE users SET total_invested = total_invested + ? WHERE id = ?");
                $user_update->bindParam(1, $this->amount);
                $user_update->bindParam(2, $this->user_id);
                $user_update->execute();

                // Process referral bonus for referrer
                $user = new User($this->conn);
                $user->id = $this->user_id;
                if ($user->readOne() && $user->referred_by) {
                    $referrer = $user->getByReferralCode($user->referred_by);
                    if ($referrer) {
                        $user->processInvestmentReferralBonus($referrer['id'], $this->amount);
                    }
                }

                $this->createNotification(
                    $this->user_id,
                    "📈 Investment Submitted",
                    "Your investment of $" . number_format($this->amount, 2) . " is under review. Expected earnings: $" . number_format($this->expected_earnings, 2),
                    'info'
                );

                $this->logActivity($this->user_id, 'investment_created', "Created investment with expected earnings: $" . $this->expected_earnings);

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
                $investment = $this->getById($investment_id);
                
                if ($investment) {
                    $message = "Your investment has been " . $status;
                    if ($status == 'active') {
                        $message = "Your investment of $" . number_format($investment['amount'], 2) . " is now active!";
                    } elseif ($status == 'completed') {
                        $message = "Your investment has been completed. Total earnings: $" . number_format($investment['expected_earnings'], 2);
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
            $base_earning = $investment['amount'] * ($investment['daily_interest'] / 100);
            
            $risk_adjustment = $this->calculateRiskAdjustment($investment['risk_tolerance']);
            $market_adjustment = $this->calculateMarketAdjustment($investment['market_trend']);
            
            $final_earning = $base_earning * $risk_adjustment * $market_adjustment;

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
                    
                    $update_query = "UPDATE investments 
                                    SET earnings_paid = earnings_paid + ? 
                                    WHERE id = ?";
                    $update_stmt = $this->conn->prepare($update_query);
                    $update_stmt->bindParam(1, $final_earning);
                    $update_stmt->bindParam(2, $investment['id']);
                    $update_stmt->execute();
                    
                    $user_query = "UPDATE users 
                                  SET total_earnings = total_earnings + ?,
                                  balance = balance + ? 
                                  WHERE id = ?";
                    $user_stmt = $this->conn->prepare($user_query);
                    $user_stmt->bindParam(1, $final_earning);
                    $user_stmt->bindParam(2, $final_earning);
                    $user_stmt->bindParam(3, $investment['user_id']);
                    $user_stmt->execute();
                    
                    $this->createNotification(
                        $investment['user_id'],
                        "💰 Daily Earnings",
                        "You earned $" . number_format($final_earning, 2) . " from your investment today!",
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
        
        $query = "SELECT p.name, COUNT(i.id) as count, SUM(i.amount) as total_amount
                 FROM investments i
                 JOIN investment_plans p ON i.plan_id = p.id
                 WHERE i.user_id = ? AND i.status = 'active'
                 GROUP BY p.id, p.name";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $analysis['plan_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $query = "SELECT risk_level, COUNT(*) as count, SUM(amount) as total_amount
                 FROM investments
                 WHERE user_id = ? AND status = 'active'
                 GROUP BY risk_level";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        $analysis['risk_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

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

    public function getAllPendingInvestments() {
        $query = "SELECT i.*, u.full_name, u.email, u.phone, p.name as plan_name
                 FROM investments i
                 JOIN users u ON i.user_id = u.id
                 JOIN investment_plans p ON i.plan_id = p.id
                 WHERE i.status = 'pending'
                 ORDER BY i.created_at DESC";
        
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function calculateExpectedEarnings() {
        $base_earnings = $this->amount * ($this->total_interest / 100);
        
        if ($this->duration > 30) {
            $compound_factor = pow(1 + COMPOUND_INTEREST_RATE, floor($this->duration / 30));
            $base_earnings *= $compound_factor;
        }
        
        $risk_adjustment = $this->getRiskAdjustment($this->risk_level);
        $base_earnings *= $risk_adjustment;
        
        return round($base_earnings, 2);
    }

    private function calculateProfitabilityScore() {
        $base_score = ($this->daily_interest * 10) + ($this->total_interest / 10);
        
        $risk_multiplier = 1.0;
        switch ($this->risk_level) {
            case 'low': $risk_multiplier = 0.8; break;
            case 'medium': $risk_multiplier = 1.0; break;
            case 'high': $risk_multiplier = 1.3; break;
        }
        
        $amount_multiplier = min(1.5, 1 + ($this->amount / 1000000));
        
        return round(($base_score * $risk_multiplier * $amount_multiplier), 2);
    }

    private function analyzeMarketTrend() {
        $trends = ['bullish', 'stable', 'volatile', 'bearish'];
        $weights = [40, 30, 20, 10];
        
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
            'low' => 0.9,
            'medium' => 1.0,
            'high' => 1.1
        ];
        
        return $adjustments[$risk_tolerance] ?? 1.0;
    }

    private function calculateMarketAdjustment($market_trend) {
        $adjustments = [
            'bullish' => 1.15,
            'stable' => 1.0,
            'volatile' => 0.9,
            'bearish' => 0.8
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
                        "Your investment in " . $investment['plan_name'] . " has been completed. Total earnings: $" . 
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
        $new_investment->amount = $investment['amount'] + $investment['earnings_paid'];
        $new_investment->daily_interest = $investment['daily_interest'];
        $new_investment->total_interest = $investment['total_interest'];
        $new_investment->duration = $investment['duration'];
        $new_investment->risk_level = $investment['risk_level'];
        $new_investment->auto_renew = true;

        if ($new_investment->create()) {
            $this->createNotification(
                $investment['user_id'],
                "🔄 Investment Auto-Renewed",
                "Your investment has been automatically renewed with compounded earnings! New amount: $" . 
                number_format($new_investment->amount, 2),
                'info'
            );
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

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            $amount = floatval($data['amount']);
            if ($amount < MIN_DEPOSIT) {
                Response::error('Minimum deposit amount is $' . number_format(MIN_DEPOSIT, 2));
            }

            $allowed_methods = ['bank_transfer', 'crypto', 'paypal', 'card', 'skrill', 'neteller'];
            if (!in_array($data['payment_method'], $allowed_methods)) {
                Response::error('Invalid payment method');
            }

            $proof_image = '';
            if (!empty($_FILES['proof_image'])) {
                $uploader = new FileUploader();
                $upload_result = $uploader->handleUpload($_FILES['proof_image'], 'deposit_proof');
                
                if (!$upload_result['success']) {
                    Response::error('File upload failed: ' . $upload_result['error']);
                }
                
                $proof_image = $upload_result['filename'];
            } elseif (!empty($data['proof_image'])) {
                $proof_image = Security::sanitizeInput($data['proof_image']);
            }

            $query = "INSERT INTO deposit_requests 
                     SET user_id=:user_id, amount=:amount, payment_method=:payment_method,
                     proof_image=:proof_image, transaction_hash=:transaction_hash, currency=:currency";

            $stmt = $this->db->prepare($query);
            $currency = $data['currency'] ?? 'USD';
            $transaction_hash = $data['transaction_hash'] ?? null;

            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":amount", $amount);
            $stmt->bindParam(":payment_method", $data['payment_method']);
            $stmt->bindParam(":proof_image", $proof_image);
            $stmt->bindParam(":transaction_hash", $transaction_hash);
            $stmt->bindParam(":currency", $currency);

            if ($stmt->execute()) {
                $deposit_id = $this->db->lastInsertId();

                $this->createNotification(
                    $user_id,
                    "💰 Deposit Request Submitted",
                    "Your deposit request of $" . number_format($amount, 2) . " is under review. You will be notified once approved.",
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

    public function getPendingDeposits() {
        try {
            $query = "SELECT dr.*, u.full_name, u.email, u.phone 
                     FROM deposit_requests dr
                     JOIN users u ON dr.user_id = u.id
                     WHERE dr.status = 'pending'
                     ORDER BY dr.created_at DESC";
            
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            $deposits = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['deposits' => $deposits], 'Pending deposits fetched successfully');
        } catch (Exception $e) {
            error_log("Get pending deposits error: " . $e->getMessage());
            Response::error('Failed to fetch pending deposits');
        }
    }

    public function getPaymentMethods() {
        $methods = [
            [
                'id' => 'bank_transfer',
                'name' => 'Bank Transfer',
                'description' => 'Direct bank transfer',
                'processing_time' => '1-3 business days',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 50000,
                'fees' => '0%'
            ],
            [
                'id' => 'crypto',
                'name' => 'Cryptocurrency',
                'description' => 'Bitcoin, Ethereum, USDT',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 100000,
                'fees' => '0%'
            ],
            [
                'id' => 'paypal',
                'name' => 'PayPal',
                'description' => 'PayPal payment',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 20000,
                'fees' => '2.9%'
            ],
            [
                'id' => 'card',
                'name' => 'Credit/Debit Card',
                'description' => 'Visa, Mastercard, American Express',
                'processing_time' => 'Instant',
                'min_amount' => MIN_DEPOSIT,
                'max_amount' => 10000,
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
                Response::error('Minimum withdrawal amount is $' . number_format(MIN_WITHDRAWAL, 2));
            }

            if ($amount > MAX_WITHDRAWAL) {
                Response::error('Maximum withdrawal amount is $' . number_format(MAX_WITHDRAWAL, 2));
            }

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

                $update_balance = $this->db->prepare("UPDATE users SET balance = balance - ? WHERE id = ?");
                $update_balance->bindParam(1, $amount);
                $update_balance->bindParam(2, $user_id);
                $update_balance->execute();

                $this->createNotification(
                    $user_id,
                    "💸 Withdrawal Request Submitted",
                    "Your withdrawal request of $" . number_format($amount, 2) . " is under review. Net amount: $" . number_format($net_amount, 2),
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

    public function getPendingWithdrawals() {
        try {
            $query = "SELECT wr.*, u.full_name, u.email, u.phone 
                     FROM withdrawal_requests wr
                     JOIN users u ON wr.user_id = u.id
                     WHERE wr.status = 'pending'
                     ORDER BY wr.created_at DESC";
            
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            $withdrawals = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['withdrawals' => $withdrawals], 'Pending withdrawals fetched successfully');
        } catch (Exception $e) {
            error_log("Get pending withdrawals error: " . $e->getMessage());
            Response::error('Failed to fetch pending withdrawals');
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

// Advanced KYC Controller with Document Verification
class KYCController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function submitKYC($user_id, $data) {
        try {
            $errors = [];
            if (empty($data['document_type'])) $errors['document_type'] = 'Document type is required';
            if (empty($data['document_number'])) $errors['document_number'] = 'Document number is required';

            if (!empty($errors)) {
                Response::validationError($errors);
            }

            $uploader = new FileUploader();
            $front_image = '';
            $back_image = '';
            $selfie_image = '';

            // Handle front image upload
            if (!empty($_FILES['front_image'])) {
                $upload_result = $uploader->handleUpload($_FILES['front_image'], 'kyc_front');
                if (!$upload_result['success']) {
                    Response::error('Front image upload failed: ' . $upload_result['error']);
                }
                $front_image = $upload_result['filename'];
            } elseif (!empty($data['front_image'])) {
                $front_image = Security::sanitizeInput($data['front_image']);
            }

            // Handle back image upload
            if (!empty($_FILES['back_image'])) {
                $upload_result = $uploader->handleUpload($_FILES['back_image'], 'kyc_back');
                if (!$upload_result['success']) {
                    Response::error('Back image upload failed: ' . $upload_result['error']);
                }
                $back_image = $upload_result['filename'];
            } elseif (!empty($data['back_image'])) {
                $back_image = Security::sanitizeInput($data['back_image']);
            }

            // Handle selfie image upload
            if (!empty($_FILES['selfie_image'])) {
                $upload_result = $uploader->handleUpload($_FILES['selfie_image'], 'kyc_selfie');
                if (!$upload_result['success']) {
                    Response::error('Selfie image upload failed: ' . $upload_result['error']);
                }
                $selfie_image = $upload_result['filename'];
            } elseif (!empty($data['selfie_image'])) {
                $selfie_image = Security::sanitizeInput($data['selfie_image']);
            }

            $query = "INSERT INTO kyc_documents 
                     SET user_id=:user_id, document_type=:document_type, document_number=:document_number,
                     front_image=:front_image, back_image=:back_image, selfie_image=:selfie_image,
                     status='pending'";

            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":document_type", $data['document_type']);
            $stmt->bindParam(":document_number", $data['document_number']);
            $stmt->bindParam(":front_image", $front_image);
            $stmt->bindParam(":back_image", $back_image);
            $stmt->bindParam(":selfie_image", $selfie_image);

            if ($stmt->execute()) {
                $kyc_id = $this->db->lastInsertId();

                $this->createNotification(
                    $user_id,
                    "📋 KYC Submitted",
                    "Your KYC documents have been submitted and are under review. You will be notified once verified.",
                    'info'
                );

                Response::success(['kyc_id' => $kyc_id], 'KYC documents submitted successfully');
            } else {
                Response::error('KYC submission failed');
            }
        } catch (Exception $e) {
            error_log("KYC submission error: " . $e->getMessage());
            Response::error('KYC submission failed: ' . $e->getMessage());
        }
    }

    public function getKYCStatus($user_id) {
        try {
            $query = "SELECT * FROM kyc_documents 
                     WHERE user_id = :user_id 
                     ORDER BY created_at DESC 
                     LIMIT 1";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();
            $kyc = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($kyc) {
                Response::success(['kyc' => $kyc], 'KYC status fetched successfully');
            } else {
                Response::success(['kyc' => null], 'No KYC submission found');
            }
        } catch (Exception $e) {
            error_log("Get KYC status error: " . $e->getMessage());
            Response::error('Failed to fetch KYC status');
        }
    }

    public function getPendingKYC() {
        try {
            $query = "SELECT kd.*, u.full_name, u.email, u.phone 
                     FROM kyc_documents kd
                     JOIN users u ON kd.user_id = u.id
                     WHERE kd.status = 'pending'
                     ORDER BY kd.created_at DESC";
            
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            $kyc_submissions = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['kyc_submissions' => $kyc_submissions], 'Pending KYC submissions fetched successfully');
        } catch (Exception $e) {
            error_log("Get pending KYC error: " . $e->getMessage());
            Response::error('Failed to fetch pending KYC submissions');
        }
    }

    public function approveKYC($admin_id, $kyc_id) {
        try {
            $this->db->beginTransaction();

            $query = "UPDATE kyc_documents 
                     SET status = 'approved', verified_by = :admin_id, verified_at = NOW()
                     WHERE id = :kyc_id";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":admin_id", $admin_id);
            $stmt->bindParam(":kyc_id", $kyc_id);
            $stmt->execute();

            $get_user_query = "SELECT user_id FROM kyc_documents WHERE id = ?";
            $get_user_stmt = $this->db->prepare($get_user_query);
            $get_user_stmt->bindParam(1, $kyc_id);
            $get_user_stmt->execute();
            $kyc = $get_user_stmt->fetch(PDO::FETCH_ASSOC);

            if ($kyc) {
                $update_user_query = "UPDATE users SET kyc_verified = TRUE WHERE id = ?";
                $update_user_stmt = $this->db->prepare($update_user_query);
                $update_user_stmt->bindParam(1, $kyc['user_id']);
                $update_user_stmt->execute();

                $this->createNotification(
                    $kyc['user_id'],
                    "✅ KYC Approved",
                    "Your KYC verification has been approved! You can now make withdrawals.",
                    'success'
                );
            }

            $this->db->commit();
            Response::success(null, 'KYC approved successfully');
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Approve KYC error: " . $e->getMessage());
            Response::error('Failed to approve KYC');
        }
    }

    public function rejectKYC($admin_id, $kyc_id, $reason) {
        try {
            $this->db->beginTransaction();

            $query = "UPDATE kyc_documents 
                     SET status = 'rejected', verified_by = :admin_id, verified_at = NOW()
                     WHERE id = :kyc_id";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":admin_id", $admin_id);
            $stmt->bindParam(":kyc_id", $kyc_id);
            $stmt->execute();

            $get_user_query = "SELECT user_id FROM kyc_documents WHERE id = ?";
            $get_user_stmt = $this->db->prepare($get_user_query);
            $get_user_stmt->bindParam(1, $kyc_id);
            $get_user_stmt->execute();
            $kyc = $get_user_stmt->fetch(PDO::FETCH_ASSOC);

            if ($kyc) {
                $this->createNotification(
                    $kyc['user_id'],
                    "❌ KYC Rejected",
                    "Your KYC verification was rejected. Reason: " . $reason . ". Please submit again.",
                    'error'
                );
            }

            $this->db->commit();
            Response::success(null, 'KYC rejected successfully');
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Reject KYC error: " . $e->getMessage());
            Response::error('Failed to reject KYC');
        }
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

// Advanced Notification Controller
class NotificationController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function getUserNotifications($user_id, $page = 1, $per_page = 20) {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT * FROM notifications 
                     WHERE user_id = :user_id 
                     ORDER BY created_at DESC 
                     LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_stmt = $this->db->prepare("SELECT COUNT(*) as total FROM notifications WHERE user_id = ?");
            $count_stmt->bindParam(1, $user_id);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            $unread_count_stmt = $this->db->prepare("SELECT COUNT(*) as unread_count FROM notifications WHERE user_id = ? AND is_read = FALSE");
            $unread_count_stmt->bindParam(1, $user_id);
            $unread_count_stmt->execute();
            $unread_count = $unread_count_stmt->fetch(PDO::FETCH_ASSOC)['unread_count'];

            Response::success([
                'notifications' => $notifications,
                'pagination' => [
                    'total' => $total,
                    'page' => $page,
                    'per_page' => $per_page,
                    'total_pages' => ceil($total / $per_page)
                ],
                'unread_count' => $unread_count
            ], 'Notifications fetched successfully');
        } catch (Exception $e) {
            error_log("Get notifications error: " . $e->getMessage());
            Response::error('Failed to fetch notifications');
        }
    }

    public function markAsRead($user_id, $notification_id) {
        try {
            $query = "UPDATE notifications SET is_read = TRUE 
                     WHERE id = :notification_id AND user_id = :user_id";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":notification_id", $notification_id);
            $stmt->bindParam(":user_id", $user_id);
            
            if ($stmt->execute()) {
                Response::success(null, 'Notification marked as read');
            } else {
                Response::error('Failed to mark notification as read');
            }
        } catch (Exception $e) {
            error_log("Mark notification as read error: " . $e->getMessage());
            Response::error('Failed to mark notification as read');
        }
    }

    public function markAllAsRead($user_id) {
        try {
            $query = "UPDATE notifications SET is_read = TRUE 
                     WHERE user_id = :user_id AND is_read = FALSE";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            
            if ($stmt->execute()) {
                Response::success(null, 'All notifications marked as read');
            } else {
                Response::error('Failed to mark notifications as read');
            }
        } catch (Exception $e) {
            error_log("Mark all notifications as read error: " . $e->getMessage());
            Response::error('Failed to mark notifications as read');
        }
    }

    public function deleteNotification($user_id, $notification_id) {
        try {
            $query = "DELETE FROM notifications 
                     WHERE id = :notification_id AND user_id = :user_id";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":notification_id", $notification_id);
            $stmt->bindParam(":user_id", $user_id);
            
            if ($stmt->execute()) {
                Response::success(null, 'Notification deleted successfully');
            } else {
                Response::error('Failed to delete notification');
            }
        } catch (Exception $e) {
            error_log("Delete notification error: " . $e->getMessage());
            Response::error('Failed to delete notification');
        }
    }
}

// Advanced Referral Controller
class ReferralController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function getReferralStats($user_id) {
        try {
            $user = new User($this->db);
            $user->id = $user_id;
            
            if (!$user->readOne()) {
                Response::error('User not found');
            }

            $referral_stats = $user->getReferralStats($user_id);
            $referrals = $this->getUserReferrals($user_id);

            Response::success([
                'stats' => $referral_stats,
                'referrals' => $referrals,
                'referral_code' => $user->referral_code,
                'referral_link' => BASE_URL . 'register?ref=' . $user->referral_code
            ], 'Referral data fetched successfully');
        } catch (Exception $e) {
            error_log("Get referral stats error: " . $e->getMessage());
            Response::error('Failed to fetch referral data');
        }
    }

    public function getReferralEarnings($user_id, $page = 1, $per_page = 20) {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT re.*, u.full_name as referred_user_name
                     FROM referral_earnings re
                     JOIN users u ON re.referred_user_id = u.id
                     WHERE re.referrer_id = :user_id
                     ORDER BY re.created_at DESC
                     LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $earnings = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_stmt = $this->db->prepare("SELECT COUNT(*) as total FROM referral_earnings WHERE referrer_id = ?");
            $count_stmt->bindParam(1, $user_id);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($earnings, $total, $page, $per_page, 'Referral earnings fetched successfully');
        } catch (Exception $e) {
            error_log("Get referral earnings error: " . $e->getMessage());
            Response::error('Failed to fetch referral earnings');
        }
    }

    private function getUserReferrals($user_id) {
        $query = "SELECT u.full_name, u.email, u.created_at, u.kyc_verified, u.status,
                         u.total_invested, u.total_earnings
                 FROM users u
                 WHERE u.referred_by = (SELECT referral_code FROM users WHERE id = ?)
                 ORDER BY u.created_at DESC";
        
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->execute();
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
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

            // User Statistics
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_users FROM users WHERE role = 'user'");
            $stmt->execute();
            $stats['total_users'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_users'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as new_users_today FROM users WHERE role = 'user' AND DATE(created_at) = CURDATE()");
            $stmt->execute();
            $stats['new_users_today'] = $stmt->fetch(PDO::FETCH_ASSOC)['new_users_today'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as new_users_week FROM users WHERE role = 'user' AND created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)");
            $stmt->execute();
            $stats['new_users_week'] = $stmt->fetch(PDO::FETCH_ASSOC)['new_users_week'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as new_users_month FROM users WHERE role = 'user' AND MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())");
            $stmt->execute();
            $stats['new_users_month'] = $stmt->fetch(PDO::FETCH_ASSOC)['new_users_month'];

            // Investment Statistics
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_investments, COALESCE(SUM(amount), 0) as total_invested FROM investments");
            $stmt->execute();
            $investment_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_investments'] = $investment_stats['total_investments'];
            $stats['total_invested'] = $investment_stats['total_invested'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as active_investments, COALESCE(SUM(amount), 0) as active_invested FROM investments WHERE status = 'active'");
            $stmt->execute();
            $active_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['active_investments'] = $active_stats['active_investments'];
            $stats['active_invested'] = $active_stats['active_invested'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as pending_investments, COALESCE(SUM(amount), 0) as pending_invested FROM investments WHERE status = 'pending'");
            $stmt->execute();
            $pending_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['pending_investments'] = $pending_stats['pending_investments'];
            $stats['pending_invested'] = $pending_stats['pending_invested'];

            // Deposit Statistics
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_deposits, COALESCE(SUM(amount), 0) as total_deposited FROM deposit_requests WHERE status = 'approved'");
            $stmt->execute();
            $deposit_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_deposits'] = $deposit_stats['total_deposits'];
            $stats['total_deposited'] = $deposit_stats['total_deposited'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as pending_deposits, COALESCE(SUM(amount), 0) as pending_deposited FROM deposit_requests WHERE status = 'pending'");
            $stmt->execute();
            $pending_deposit_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['pending_deposits'] = $pending_deposit_stats['pending_deposits'];
            $stats['pending_deposited'] = $pending_deposit_stats['pending_deposited'];

            // Withdrawal Statistics
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_withdrawals, COALESCE(SUM(amount), 0) as total_withdrawn FROM withdrawal_requests WHERE status = 'approved'");
            $stmt->execute();
            $withdrawal_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['total_withdrawals'] = $withdrawal_stats['total_withdrawals'];
            $stats['total_withdrawn'] = $withdrawal_stats['total_withdrawn'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as pending_withdrawals, COALESCE(SUM(amount), 0) as pending_withdrawn FROM withdrawal_requests WHERE status = 'pending'");
            $stmt->execute();
            $pending_withdrawal_stats = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['pending_withdrawals'] = $pending_withdrawal_stats['pending_withdrawals'];
            $stats['pending_withdrawn'] = $pending_withdrawal_stats['pending_withdrawn'];

            // Platform Earnings
            $stmt = $this->db->prepare("SELECT COALESCE(SUM(platform_fee), 0) as total_platform_fees FROM withdrawal_requests WHERE status = 'approved'");
            $stmt->execute();
            $stats['total_platform_fees'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_platform_fees'];

            $stmt = $this->db->prepare("SELECT COALESCE(SUM(referral_earnings), 0) as total_referral_earnings FROM users");
            $stmt->execute();
            $stats['total_referral_earnings'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_referral_earnings'];

            // KYC Statistics
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_kyc_submissions FROM kyc_documents");
            $stmt->execute();
            $stats['total_kyc_submissions'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_kyc_submissions'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as pending_kyc FROM kyc_documents WHERE status = 'pending'");
            $stmt->execute();
            $stats['pending_kyc'] = $stmt->fetch(PDO::FETCH_ASSOC)['pending_kyc'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as approved_kyc FROM kyc_documents WHERE status = 'approved'");
            $stmt->execute();
            $stats['approved_kyc'] = $stmt->fetch(PDO::FETCH_ASSOC)['approved_kyc'];

            // Recent Activity
            $stmt = $this->db->prepare("SELECT action, COUNT(*) as count FROM audit_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY action");
            $stmt->execute();
            $stats['recent_activity'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // System Health
            $stmt = $this->db->prepare("SELECT COUNT(*) as total_notifications FROM notifications");
            $stmt->execute();
            $stats['total_notifications'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_notifications'];

            $stmt = $this->db->prepare("SELECT COUNT(*) as total_audit_logs FROM audit_logs");
            $stmt->execute();
            $stats['total_audit_logs'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_audit_logs'];

            Response::success(['stats' => $stats], 'Dashboard statistics fetched successfully');
        } catch (Exception $e) {
            error_log("Get admin stats error: " . $e->getMessage());
            Response::error('Failed to fetch admin statistics');
        }
    }

    public function getFinancialOverview() {
        try {
            $overview = [];

            // Daily earnings for the last 30 days
            $stmt = $this->db->prepare("
                SELECT earning_date, SUM(amount) as daily_earnings 
                FROM daily_earnings 
                WHERE earning_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                GROUP BY earning_date 
                ORDER BY earning_date
            ");
            $stmt->execute();
            $overview['daily_earnings'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Monthly investment totals
            $stmt = $this->db->prepare("
                SELECT 
                    YEAR(created_at) as year,
                    MONTH(created_at) as month,
                    COUNT(*) as investment_count,
                    SUM(amount) as investment_amount
                FROM investments 
                WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
                GROUP BY YEAR(created_at), MONTH(created_at)
                ORDER BY year DESC, month DESC
            ");
            $stmt->execute();
            $overview['monthly_investments'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // User growth
            $stmt = $this->db->prepare("
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as user_count
                FROM users 
                WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                GROUP BY DATE(created_at)
                ORDER BY date
            ");
            $stmt->execute();
            $overview['user_growth'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Top investors
            $stmt = $this->db->prepare("
                SELECT 
                    u.full_name,
                    u.email,
                    SUM(i.amount) as total_invested,
                    COUNT(i.id) as investment_count
                FROM users u
                JOIN investments i ON u.id = i.user_id
                WHERE i.status = 'active'
                GROUP BY u.id
                ORDER BY total_invested DESC
                LIMIT 10
            ");
            $stmt->execute();
            $overview['top_investors'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            Response::success(['overview' => $overview], 'Financial overview fetched successfully');
        } catch (Exception $e) {
            error_log("Get financial overview error: " . $e->getMessage());
            Response::error('Failed to fetch financial overview');
        }
    }

    public function approveDeposit($admin_id, $deposit_id) {
        try {
            $this->db->beginTransaction();

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

            $update_stmt = $this->db->prepare("UPDATE deposit_requests SET status = 'approved', processed_by = ?, processed_at = NOW() WHERE id = ?");
            $update_stmt->bindParam(1, $admin_id);
            $update_stmt->bindParam(2, $deposit_id);
            $update_stmt->execute();

            $user_stmt = $this->db->prepare("UPDATE users SET balance = balance + ? WHERE id = ?");
            $user_stmt->bindParam(1, $deposit['amount']);
            $user_stmt->bindParam(2, $deposit['user_id']);
            $user_stmt->execute();

            $txn_stmt = $this->db->prepare("INSERT INTO transactions SET user_id = ?, type = 'deposit', amount = ?, status = 'completed', description = 'Deposit approved'");
            $txn_stmt->bindParam(1, $deposit['user_id']);
            $txn_stmt->bindParam(2, $deposit['amount']);
            $txn_stmt->execute();

            $notif_stmt = $this->db->prepare("INSERT INTO notifications SET user_id = ?, title = '💰 Deposit Approved', message = ?, type = 'success', priority = 'high'");
            $message = "Your deposit of $" . number_format($deposit['amount'], 2) . " has been approved and added to your balance.";
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

            $update_stmt = $this->db->prepare("UPDATE withdrawal_requests SET status = 'approved', processed_by = ?, processed_at = NOW() WHERE id = ?");
            $update_stmt->bindParam(1, $admin_id);
            $update_stmt->bindParam(2, $withdrawal_id);
            $update_stmt->execute();

            $txn_stmt = $this->db->prepare("INSERT INTO transactions SET user_id = ?, type = 'withdrawal', amount = ?, status = 'completed', description = 'Withdrawal approved'");
            $txn_stmt->bindParam(1, $withdrawal['user_id']);
            $txn_stmt->bindParam(2, $withdrawal['amount']);
            $txn_stmt->execute();

            $notif_stmt = $this->db->prepare("INSERT INTO notifications SET user_id = ?, title = '💸 Withdrawal Approved', message = ?, type = 'success', priority = 'high'");
            $message = "Your withdrawal of $" . number_format($withdrawal['amount'], 2) . " has been approved and will be processed shortly.";
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

    public function getSystemLogs($page = 1, $per_page = 50, $type = 'all') {
        try {
            $offset = ($page - 1) * $per_page;
            
            $query = "SELECT al.*, u.full_name, u.email 
                     FROM audit_logs al
                     LEFT JOIN users u ON al.user_id = u.id";
            
            if ($type !== 'all') {
                $query .= " WHERE al.action = :action";
            }
            
            $query .= " ORDER BY al.created_at DESC LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            
            if ($type !== 'all') {
                $stmt->bindParam(":action", $type);
            }
            
            $stmt->bindParam(":limit", $per_page, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $count_query = "SELECT COUNT(*) as total FROM audit_logs";
            if ($type !== 'all') {
                $count_query .= " WHERE action = :action";
            }
            
            $count_stmt = $this->db->prepare($count_query);
            if ($type !== 'all') {
                $count_stmt->bindParam(":action", $type);
            }
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];

            Response::paginated($logs, $total, $page, $per_page, 'System logs fetched successfully');
        } catch (Exception $e) {
            error_log("Get system logs error: " . $e->getMessage());
            Response::error('Failed to fetch system logs');
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
                ], 'Registration successful. Welcome to Raw Wealthy! You received a $100 welcome bonus!');
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
            if ($amount < 3500) { // Updated minimum investment
                Response::error('Minimum investment amount is $3,500');
            }

            if ($amount > 300000) { // Updated maximum investment
                Response::error('Maximum investment amount is $300,000');
            }

            $user_stmt = $this->db->prepare("SELECT balance FROM users WHERE id = ?");
            $user_stmt->bindParam(1, $user_id);
            $user_stmt->execute();
            $user = $user_stmt->fetch(PDO::FETCH_ASSOC);

            if ($user['balance'] < $amount) {
                Response::error('Insufficient balance for investment');
            }

            $plan_stmt = $this->db->prepare("SELECT * FROM investment_plans WHERE id = ?");
            $plan_stmt->bindParam(1, $data['plan_id']);
            $plan_stmt->execute();
            $plan = $plan_stmt->fetch(PDO::FETCH_ASSOC);

            if (!$plan) {
                Response::error('Invalid investment plan');
            }

            $proof_image = '';
            if (!empty($_FILES['proof_image'])) {
                $uploader = new FileUploader();
                $upload_result = $uploader->handleUpload($_FILES['proof_image'], 'investment_proof');
                
                if (!$upload_result['success']) {
                    Response::error('File upload failed: ' . $upload_result['error']);
                }
                
                $proof_image = $upload_result['filename'];
            } elseif (!empty($data['proof_image'])) {
                $proof_image = Security::sanitizeInput($data['proof_image']);
            }

            $this->investment->user_id = $user_id;
            $this->investment->plan_id = intval($data['plan_id']);
            $this->investment->amount = $amount;
            $this->investment->daily_interest = floatval($plan['daily_interest']);
            $this->investment->total_interest = floatval($plan['total_interest']);
            $this->investment->duration = intval($plan['duration']);
            $this->investment->proof_image = $proof_image;
            $this->investment->auto_renew = boolval($data['auto_renew'] ?? false);
            $this->investment->risk_level = $plan['risk_level'];

            $investment_id = $this->investment->create();

            if ($investment_id) {
                $update_balance = $this->db->prepare("UPDATE users SET balance = balance - ? WHERE id = ?");
                $update_balance->bindParam(1, $amount);
                $update_balance->bindParam(2, $user_id);
                $update_balance->execute();

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

    public function getPendingInvestments() {
        try {
            $pending_investments = $this->investment->getAllPendingInvestments();
            Response::success(['investments' => $pending_investments], 'Pending investments fetched successfully');
        } catch (Exception $e) {
            error_log("Get pending investments error: " . $e->getMessage());
            Response::error('Failed to fetch pending investments');
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
    private $kycController;
    private $notificationController;
    private $referralController;
    private $adminController;

    public function __construct() {
        $database = new Database();
        $this->db = $database->getConnection();
        
        $this->authController = new AuthController($this->db);
        $this->investmentController = new InvestmentController($this->db);
        $this->depositController = new DepositController($this->db);
        $this->withdrawalController = new WithdrawalController($this->db);
        $this->kycController = new KYCController($this->db);
        $this->notificationController = new NotificationController($this->db);
        $this->referralController = new ReferralController($this->db);
        $this->adminController = new AdminController($this->db);
    }

    public function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $path = str_replace('/index.php', '', $path);
        
        if ($method === 'OPTIONS') {
            Response::success([]);
        }

        try {
            switch ($path) {
                case '/api/register':
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->authController->register($data);
                    }
                    break;

                case '/api/login':
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->authController->login($data);
                    }
                    break;

                case '/api/profile':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->authController->getProfile($user['user_id']);
                    } elseif ($method === 'PUT') {
                        $data = $this->getInputData();
                        $this->authController->updateProfile($user['user_id'], $data);
                    }
                    break;

                case '/api/profile/password':
                    $user = $this->authenticate();
                    if ($method === 'PUT') {
                        $data = $this->getInputData();
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
                        $data = $this->getInputData();
                        $this->authController->disable2FA($user['user_id'], $data['code']);
                    }
                    break;

                case '/api/investments':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->investmentController->getUserInvestments($user['user_id'], $page);
                    } elseif ($method === 'POST') {
                        $data = $this->getInputData();
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
                        $data = $this->getInputData();
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
                        $data = $this->getInputData();
                        $this->withdrawalController->createWithdrawal($user['user_id'], $data);
                    }
                    break;

                case '/api/kyc/submit':
                    $user = $this->authenticate();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->kycController->submitKYC($user['user_id'], $data);
                    }
                    break;

                case '/api/kyc/status':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->kycController->getKYCStatus($user['user_id']);
                    }
                    break;

                case '/api/notifications':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->notificationController->getUserNotifications($user['user_id'], $page);
                    }
                    break;

                case '/api/notifications/read':
                    $user = $this->authenticate();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->notificationController->markAsRead($user['user_id'], $data['notification_id']);
                    }
                    break;

                case '/api/notifications/read-all':
                    $user = $this->authenticate();
                    if ($method === 'POST') {
                        $this->notificationController->markAllAsRead($user['user_id']);
                    }
                    break;

                case '/api/notifications/delete':
                    $user = $this->authenticate();
                    if ($method === 'DELETE') {
                        $data = $this->getInputData();
                        $this->notificationController->deleteNotification($user['user_id'], $data['notification_id']);
                    }
                    break;

                case '/api/referrals/stats':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $this->referralController->getReferralStats($user['user_id']);
                    }
                    break;

                case '/api/referrals/earnings':
                    $user = $this->authenticate();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $this->referralController->getReferralEarnings($user['user_id'], $page);
                    }
                    break;

                case '/api/admin/dashboard':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->adminController->getDashboardStats();
                    }
                    break;

                case '/api/admin/financial-overview':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->adminController->getFinancialOverview();
                    }
                    break;

                case '/api/admin/approve-deposit':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->adminController->approveDeposit($user['user_id'], $data['deposit_id']);
                    }
                    break;

                case '/api/admin/approve-withdrawal':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->adminController->approveWithdrawal($user['user_id'], $data['withdrawal_id']);
                    }
                    break;

                case '/api/admin/approve-investment':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->adminController->approveInvestment($user['user_id'], $data['investment_id']);
                    }
                    break;

                case '/api/admin/approve-kyc':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->kycController->approveKYC($user['user_id'], $data['kyc_id']);
                    }
                    break;

                case '/api/admin/reject-kyc':
                    $user = $this->authenticateAdmin();
                    if ($method === 'POST') {
                        $data = $this->getInputData();
                        $this->kycController->rejectKYC($user['user_id'], $data['kyc_id'], $data['reason']);
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
                        $data = $this->getInputData();
                        $this->adminController->updateUserStatus($data['user_id'], $data['status']);
                    }
                    break;

                case '/api/admin/pending-deposits':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->depositController->getPendingDeposits();
                    }
                    break;

                case '/api/admin/pending-withdrawals':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->withdrawalController->getPendingWithdrawals();
                    }
                    break;

                case '/api/admin/pending-investments':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->investmentController->getPendingInvestments();
                    }
                    break;

                case '/api/admin/pending-kyc':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $this->kycController->getPendingKYC();
                    }
                    break;

                case '/api/admin/system-logs':
                    $user = $this->authenticateAdmin();
                    if ($method === 'GET') {
                        $page = $_GET['page'] ?? 1;
                        $type = $_GET['type'] ?? 'all';
                        $this->adminController->getSystemLogs($page, 50, $type);
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

    private function getInputData() {
        $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
        
        if (strpos($content_type, 'application/json') !== false) {
            return json_decode(file_get_contents('php://input'), true);
        } elseif (strpos($content_type, 'multipart/form-data') !== false) {
            return array_merge($_POST, $_FILES);
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
                currency VARCHAR(10) DEFAULT 'USD',
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS kyc_documents (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                document_type ENUM('national_id', 'passport', 'driver_license') NOT NULL,
                document_number VARCHAR(100) NOT NULL,
                front_image VARCHAR(255) NOT NULL,
                back_image VARCHAR(255),
                selfie_image VARCHAR(255),
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                verified_by INT NULL,
                verified_at TIMESTAMP NULL,
                rejection_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            "CREATE TABLE IF NOT EXISTS referral_earnings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                referrer_id INT NOT NULL,
                referred_user_id INT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                type ENUM('signup_bonus', 'investment_commission') DEFAULT 'signup_bonus',
                status ENUM('pending', 'paid') DEFAULT 'pending',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (referred_user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_referrer_id (referrer_id),
                INDEX idx_referred_user_id (referred_user_id),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];

        foreach ($tables_sql as $sql) {
            $db->exec($sql);
        }

        $check_admin = $db->prepare("SELECT id FROM users WHERE email = 'admin@rawwealthy.com'");
        $check_admin->execute();
        
        if ($check_admin->rowCount() == 0) {
            $admin_password = Security::hashPassword('Admin123!');
            $insert_admin = $db->prepare("INSERT INTO users (full_name, email, password_hash, role, referral_code, kyc_verified, balance, risk_tolerance) VALUES ('Admin User', 'admin@rawwealthy.com', ?, 'admin', 'ADMIN001', TRUE, 100000.00, 'medium')");
            $insert_admin->execute([$admin_password]);
        }

        $check_plans = $db->prepare("SELECT id FROM investment_plans");
        $check_plans->execute();
        
        if ($check_plans->rowCount() == 0) {
            // 25 Investment Plans with $3,500 - $300,000 range
            $plans_sql = "INSERT INTO investment_plans (name, min_amount, max_amount, daily_interest, total_interest, duration, description, risk_level, features) VALUES 
                ('Bronze Starter', 3500, 10000, 2.5, 75, 30, 'Perfect for beginners with low risk tolerance. Stable returns with capital protection.', 'low', '[\"Capital Protection\", \"Stable Returns\", \"Beginner Friendly\", \"Low Risk\"]'),
                ('Silver Growth', 5000, 25000, 3.2, 96, 30, 'Balanced growth with moderate risk. Ideal for steady portfolio expansion.', 'medium', '[\"Balanced Growth\", \"Moderate Risk\", \"Portfolio Diversification\", \"Steady Returns\"]'),
                ('Gold Premium', 10000, 50000, 3.8, 114, 30, 'Premium investment with enhanced returns. Professional portfolio management.', 'medium', '[\"Enhanced Returns\", \"Professional Management\", \"Premium Service\", \"Medium Risk\"]'),
                ('Platinum Elite', 15000, 75000, 4.2, 126, 30, 'Elite investment tier with superior returns and personalized strategy.', 'high', '[\"Superior Returns\", \"Personalized Strategy\", \"Elite Tier\", \"High Reward\"]'),
                ('Diamond Exclusive', 25000, 100000, 4.8, 144, 30, 'Exclusive high-yield investment for serious investors seeking maximum growth.', 'high', '[\"High Yield\", \"Exclusive Access\", \"Maximum Growth\", \"Premium Support\"]'),
                ('Titanium Premium', 35000, 150000, 5.2, 156, 30, 'Premium titanium-level investment with advanced risk management.', 'high', '[\"Advanced Risk Management\", \"Premium Returns\", \"Titanium Level\", \"Expert Advisory\"]'),
                ('Crypto Growth', 5000, 50000, 6.5, 195, 30, 'Cryptocurrency portfolio with high growth potential and dynamic trading.', 'high', '[\"Cryptocurrency\", \"High Growth\", \"Dynamic Trading\", \"Market Analysis\"]'),
                ('Real Estate Income', 20000, 200000, 3.5, 105, 30, 'Commercial real estate investments generating steady rental income.', 'medium', '[\"Real Estate\", \"Rental Income\", \"Property Investment\", \"Steady Cashflow\"]'),
                ('Tech Innovation', 15000, 100000, 5.8, 174, 30, 'Technology sector investments focusing on innovation and disruption.', 'high', '[\"Technology\", \"Innovation\", \"High Growth\", \"Sector Focus\"]'),
                ('Green Energy Fund', 10000, 80000, 4.5, 135, 30, 'Sustainable energy investments supporting environmental initiatives.', 'medium', '[\"Green Energy\", \"Sustainability\", \"ESG Focus\", \"Future Proof\"]'),
                ('Healthcare Growth', 12000, 90000, 4.3, 129, 30, 'Healthcare sector investments with strong growth fundamentals.', 'medium', '[\"Healthcare\", \"Growth Sector\", \"Stable Demand\", \"Long Term\"]'),
                ('AI Technology', 18000, 120000, 6.2, 186, 30, 'Artificial intelligence and machine learning technology investments.', 'high', '[\"Artificial Intelligence\", \"Machine Learning\", \"Cutting Edge\", \"High Potential\"]'),
                ('Emerging Markets', 8000, 60000, 5.5, 165, 30, 'Diversified emerging markets portfolio with growth opportunities.', 'high', '[\"Emerging Markets\", \"Diversification\", \"Growth Opportunities\", \"Global Exposure\"]'),
                ('Commodities Plus', 10000, 75000, 4.8, 144, 30, 'Commodities investment including precious metals and energy resources.', 'medium', '[\"Commodities\", \"Precious Metals\", \"Energy Resources\", \"Inflation Hedge\"]'),
                ('Infrastructure Fund', 25000, 200000, 3.8, 114, 30, 'Global infrastructure development projects with long-term stability.', 'low', '[\"Infrastructure\", \"Long Term\", \"Stable Returns\", \"Government Backed\"]'),
                ('Biotech Innovation', 20000, 150000, 6.8, 204, 30, 'Biotechnology and pharmaceutical research investments.', 'high', '[\"Biotechnology\", \"Pharmaceuticals\", \"Research\", \"High Risk High Reward\"]'),
                ('Renewable Energy', 15000, 120000, 4.2, 126, 30, 'Renewable energy projects including solar and wind power generation.', 'medium', '[\"Renewable Energy\", \"Solar Power\", \"Wind Energy\", \"Sustainable\"]'),
                ('E-commerce Growth', 12000, 90000, 5.2, 156, 30, 'E-commerce and digital retail sector investments.', 'medium', '[\"E-commerce\", \"Digital Retail\", \"Online Business\", \"Growth Sector\"]'),
                ('Fintech Revolution', 18000, 140000, 6.5, 195, 30, 'Financial technology innovations and digital banking solutions.', 'high', '[\"Fintech\", \"Digital Banking\", \"Innovation\", \"Disruptive Technology\"]'),
                ('Space Technology', 30000, 250000, 7.2, 216, 30, 'Space exploration and satellite technology investments.', 'high', '[\"Space Technology\", \"Satellite\", \"Exploration\", \"Cutting Edge\"]'),
                ('Quantum Computing', 35000, 300000, 7.8, 234, 30, 'Quantum computing research and development investments.', 'high', '[\"Quantum Computing\", \"Research\", \"Advanced Technology\", \"Future Tech\"]'),
                ('Metaverse Ventures', 20000, 180000, 6.8, 204, 30, 'Metaverse and virtual reality technology investments.', 'high', '[\"Metaverse\", \"Virtual Reality\", \"Digital Worlds\", \"Emerging Tech\"]'),
                ('Blockchain Assets', 15000, 120000, 7.5, 225, 30, 'Blockchain technology and digital asset investments.', 'high', '[\"Blockchain\", \"Digital Assets\", \"Cryptocurrency\", \"Decentralized\"]'),
                ('Sustainable Agriculture', 10000, 80000, 4.0, 120, 30, 'Sustainable farming and agricultural technology investments.', 'medium', '[\"Agriculture\", \"Sustainable\", \"Food Security\", \"Technology\"]'),
                ('Water Resources', 12000, 100000, 3.8, 114, 30, 'Water treatment and resource management investments.', 'low', '[\"Water Resources\", \"Treatment\", \"Management\", \"Essential Service\"]')";
            
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
    if (!is_dir(__DIR__ . '/logs')) {
        mkdir(__DIR__ . '/logs', 0755, true);
    }
    
    if (!is_dir(UPLOAD_PATH)) {
        mkdir(UPLOAD_PATH, 0755, true);
    }

    $database = new Database();
    $db = $database->getConnection();
    
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

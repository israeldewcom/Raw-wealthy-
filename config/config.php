<?php
// Add this to config/config.php at the TOP
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
// Application configuration
define('APP_NAME', 'Raw Wealthy Investment Platform');
define('APP_VERSION', '4.0.0');
define('APP_URL', 'http://localhost:8000');
define('UPLOAD_PATH', __DIR__ . '/../uploads/');

// JWT Secret (for production)
define('JWT_SECRET', 'your-secret-key-here');

// Enable error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);
?>

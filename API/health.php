// Create a health check endpoint to test dependencies
// api/health.php
<?php
header("Content-Type: application/json");

$health = [
    "status" => "checking",
    "timestamp" => time(),
    "checks" => []
];

// Check PHP version
$health["checks"]["php_version"] = [
    "status" => version_compare(PHP_VERSION, '7.4.0') >= 0 ? "healthy" : "unhealthy",
    "version" => PHP_VERSION
];

// Check database
try {
    require_once '../config/database.php';
    $database = new Database();
    $conn = $database->getConnection();
    $health["checks"]["database"] = ["status" => "healthy"];
} catch (Exception $e) {
    $health["checks"]["database"] = [
        "status" => "unhealthy", 
        "error" => $e->getMessage()
    ];
}

// Check required extensions
$required_extensions = ['pdo', 'pdo_mysql', 'json', 'mbstring'];
foreach ($required_extensions as $ext) {
    $health["checks"]["extension_$ext"] = [
        "status" => extension_loaded($ext) ? "healthy" : "unhealthy"
    ];
}

// Determine overall status
$unhealthy = array_filter($health["checks"], function($check) {
    return $check["status"] === "unhealthy";
});

$health["status"] = empty($unhealthy) ? "healthy" : "unhealthy";

http_response_code($health["status"] === "healthy" ? 200 : 503);
echo json_encode($health);
?>

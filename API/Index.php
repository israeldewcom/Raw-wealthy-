<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

include_once '../config/database.php';
include_once '../middleware/AuthMiddleware.php';
include_once '../models/User.php';
include_once '../models/Investment.php';

$database = new Database();
$db = $database->getConnection();
$auth = new AuthMiddleware($db);

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = str_replace('/api/', '', $path);

switch($path) {
    case 'register':
        if ($method == 'POST') include 'register.php';
        break;
    case 'login':
        if ($method == 'POST') include 'login.php';
        break;
    case 'profile':
        $user = $auth->authenticate();
        if ($user) {
            if ($method == 'GET') include 'profile.php';
            if ($method == 'PUT') include 'update_profile.php';
        }
        break;
    case 'investment-plans':
        if ($method == 'GET') include 'investment_plans.php';
        break;
    case 'investments':
        $user = $auth->authenticate();
        if ($user) {
            if ($method == 'GET') include 'get_investments.php';
            if ($method == 'POST') include 'create_investment.php';
        }
        break;
    case 'deposits':
        $user = $auth->authenticate();
        if ($user && $method == 'POST') include 'create_deposit.php';
        break;
    case 'withdrawals':
        $user = $auth->authenticate();
        if ($user && $method == 'POST') include 'create_withdrawal.php';
        break;
    case 'admin/dashboard':
        $user = $auth->authenticate();
        if ($user && $auth->requireAdmin($user)) {
            include 'admin/dashboard.php';
        }
        break;
    default:
        http_response_code(404);
        echo json_encode(array("message" => "Endpoint not found."));
        break;
}
?>

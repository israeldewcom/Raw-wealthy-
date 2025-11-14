<?php
class AuthMiddleware {
    private $conn;
    private $user;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function authenticate() {
        $headers = getallheaders();
        $token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

        if (!$token) {
            http_response_code(401);
            echo json_encode(array("message" => "Access denied. No token provided."));
            return false;
        }

        // In a real application, you would validate JWT tokens
        // For simplicity, we'll use a basic token validation
        $query = "SELECT id, full_name, email, phone, balance, total_earnings, referral_earnings, 
                         kyc_verified, role, referral_code, risk_tolerance, investment_strategy 
                  FROM users WHERE id = ?";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $token);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            return $user;
        }

        http_response_code(401);
        echo json_encode(array("message" => "Invalid token."));
        return false;
    }

    public function requireAdmin($user) {
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(array("message" => "Access denied. Admin privileges required."));
            return false;
        }
        return true;
    }
}
?>

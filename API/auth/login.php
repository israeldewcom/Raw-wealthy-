<?php
require_once '../../models/User.php';
require_once '../../utils/JWT.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!empty($data->email) && !empty($data->password)) {
        $user = new User($db);
        $user->email = $data->email;

        try {
            if ($user->emailExists() && password_verify($data->password, $user->password)) {
                // Check if user is active
                if ($user->status !== 'active') {
                    throw new Exception("Your account has been suspended. Please contact support.", 403);
                }

                // Handle 2FA if enabled
                if ($user->two_factor_enabled && empty($data->two_factor_code)) {
                    echo json_encode([
                        "success" => true,
                        "requires_2fa" => true,
                        "message" => "Two-factor authentication required."
                    ]);
                    return;
                }

                // Verify 2FA code if provided
                if ($user->two_factor_enabled && !empty($data->two_factor_code)) {
                    if (!$this->verify2FACode($user->two_factor_secret, $data->two_factor_code)) {
                        throw new Exception("Invalid 2FA code.", 401);
                    }
                }

                // Update last login
                $user->updateLastLogin();

                // Generate JWT token
                $token = JWT::generateToken($user->id, $user->role);

                // Get user data
                $user_data = $user->getUserProfile();

                echo json_encode([
                    "success" => true,
                    "message" => "Login successful.",
                    "data" => [
                        "token" => $token,
                        "user" => $user_data,
                        "requires_2fa" => false
                    ]
                ]);
            } else {
                throw new Exception("Invalid email or password.", 401);
            }
        } catch (Exception $e) {
            http_response_code($e->getCode() ?: 401);
            echo json_encode([
                "success" => false,
                "message" => $e->getMessage()
            ]);
        }
    } else {
        http_response_code(400);
        echo json_encode([
            "success" => false,
            "message" => "Email and password are required."
        ]);
    }
}

private function verify2FACode($secret, $code) {
    // Implement TOTP verification
    // For demo, accept any 6-digit code
    return preg_match('/^\d{6}$/', $code);
}
?>

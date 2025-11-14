<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!empty($data->email) && !empty($data->password)) {
        $user = new User($db);
        
        $user->email = $data->email;
        $email_exists = $user->emailExists();

        if ($email_exists && password_verify($data->password, $user->password)) {
            // Check if 2FA is required
            if ($user->two_factor_enabled && empty($data->two_factor_code)) {
                echo json_encode(array(
                    "success" => true,
                    "requires_2fa" => true,
                    "message" => "Two-factor authentication required."
                ));
                return;
            }

            // Verify 2FA code if provided
            if ($user->two_factor_enabled && !empty($data->two_factor_code)) {
                // In a real app, verify the TOTP code
                // For demo, we'll accept any 6-digit code
                if (!preg_match('/^\d{6}$/', $data->two_factor_code)) {
                    http_response_code(401);
                    echo json_encode(array("success" => false, "message" => "Invalid 2FA code."));
                    return;
                }
            }

            // Get complete user data
            $user_query = "SELECT id, full_name, email, phone, balance, total_earnings, referral_earnings, 
                                  kyc_verified, role, referral_code, risk_tolerance, investment_strategy 
                           FROM users WHERE id = ?";
            $user_stmt = $db->prepare($user_query);
            $user_stmt->bindParam(1, $user->id);
            $user_stmt->execute();
            $user_data = $user_stmt->fetch(PDO::FETCH_ASSOC);

            echo json_encode(array(
                "success" => true,
                "message" => "Login successful.",
                "data" => array(
                    "token" => $user->id,
                    "user" => $user_data,
                    "requires_2fa" => false
                )
            ));
        } else {
            http_response_code(401);
            echo json_encode(array("success" => false, "message" => "Invalid email or password."));
        }
    } else {
        http_response_code(400);
        echo json_encode(array("success" => false, "message" => "Email and password are required."));
    }
}
?>

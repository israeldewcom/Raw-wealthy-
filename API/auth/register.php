<?php
require_once '../../models/User.php';
require_once '../../utils/JWT.php';
require_once '../../utils/Email.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!empty($data->full_name) && !empty($data->email) && !empty($data->password)) {
        $user = new User($db);
        
        $user->full_name = $data->full_name;
        $user->email = $data->email;
        $user->phone = $data->phone ?? '';
        $user->password = $data->password;
        $user->referred_by = $data->referral_code ?? '';
        $user->risk_tolerance = $data->risk_tolerance ?? 'medium';
        $user->investment_strategy = $data->investment_strategy ?? 'balanced';

        try {
            if ($user->emailExists()) {
                throw new Exception("Email already exists.", 400);
            }

            if ($user->create()) {
                // Generate JWT token
                $token = JWT::generateToken($user->id, $user->role);

                // Send verification email
                $email = new Email();
                $email->sendVerificationEmail($user->email, $user->full_name, $user->email_verification_token);

                // Get user data without sensitive information
                $user_data = $user->getUserProfile();

                http_response_code(201);
                echo json_encode([
                    "success" => true,
                    "message" => "User registered successfully. Please check your email for verification.",
                    "data" => [
                        "token" => $token,
                        "user" => $user_data
                    ]
                ]);
            } else {
                throw new Exception("Unable to register user.", 500);
            }
        } catch (Exception $e) {
            http_response_code($e->getCode() ?: 500);
            echo json_encode([
                "success" => false,
                "message" => $e->getMessage()
            ]);
        }
    } else {
        http_response_code(400);
        echo json_encode([
            "success" => false,
            "message" => "Full name, email, and password are required."
        ]);
    }
}
?>

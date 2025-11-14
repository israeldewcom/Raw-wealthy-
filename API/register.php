<?php
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

        if ($user->emailExists()) {
            http_response_code(400);
            echo json_encode(array("success" => false, "message" => "Email already exists."));
        } else {
            if ($user->create()) {
                // Process referral if exists
                if (!empty($data->referral_code)) {
                    $referrer_query = "SELECT id FROM users WHERE referral_code = ?";
                    $referrer_stmt = $db->prepare($referrer_query);
                    $referrer_stmt->bindParam(1, $data->referral_code);
                    $referrer_stmt->execute();
                    
                    if ($referrer_stmt->rowCount() > 0) {
                        $referrer = $referrer_stmt->fetch(PDO::FETCH_ASSOC);
                        $ref_insert = "INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)";
                        $ref_stmt = $db->prepare($ref_insert);
                        $ref_stmt->bindParam(1, $referrer['id']);
                        $ref_stmt->bindParam(2, $user->id);
                        $ref_stmt->execute();
                    }
                }

                // Get the created user data
                $user_query = "SELECT id, full_name, email, phone, balance, total_earnings, referral_earnings, 
                                      kyc_verified, role, referral_code, risk_tolerance, investment_strategy 
                               FROM users WHERE id = ?";
                $user_stmt = $db->prepare($user_query);
                $user_stmt->bindParam(1, $user->id);
                $user_stmt->execute();
                $user_data = $user_stmt->fetch(PDO::FETCH_ASSOC);

                http_response_code(201);
                echo json_encode(array(
                    "success" => true,
                    "message" => "User registered successfully.",
                    "data" => array(
                        "token" => $user->id, // Using user ID as token for simplicity
                        "user" => $user_data
                    )
                ));
            } else {
                http_response_code(503);
                echo json_encode(array("success" => false, "message" => "Unable to register user."));
            }
        }
    } else {
        http_response_code(400);
        echo json_encode(array("success" => false, "message" => "Unable to register user. Data is incomplete."));
    }
}
?>

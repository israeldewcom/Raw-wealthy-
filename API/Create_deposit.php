<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $auth->authenticate();
    if ($user) {
        $data = json_decode(file_get_contents("php://input"));

        if (!empty($data->amount) && !empty($data->payment_method)) {
            // Validate amount
            if ($data->amount < 3500) {
                http_response_code(400);
                echo json_encode(array("success" => false, "message" => "Minimum deposit is ₦3,500."));
                return;
            }

            // Create deposit record
            $deposit_query = "INSERT INTO deposits (user_id, amount, payment_method, transaction_hash, status) 
                             VALUES (?, ?, ?, ?, 'pending')";
            $deposit_stmt = $db->prepare($deposit_query);
            $deposit_stmt->bindParam(1, $user['id']);
            $deposit_stmt->bindParam(2, $data->amount);
            $deposit_stmt->bindParam(3, $data->payment_method);
            $deposit_stmt->bindParam(4, $data->transaction_hash);
            $deposit_stmt->execute();

            $deposit_id = $db->lastInsertId();

            echo json_encode(array(
                "success" => true,
                "message" => "Deposit request submitted successfully.",
                "data" => array(
                    "deposit_id" => $deposit_id
                )
            ));
        } else {
            http_response_code(400);
            echo json_encode(array("success" => false, "message" => "Amount and payment method are required."));
        }
    }
}
?>

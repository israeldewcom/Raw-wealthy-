
<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $auth->authenticate();
    if ($user) {
        $data = json_decode(file_get_contents("php://input"));

        if (!empty($data->amount) && !empty($data->payment_method)) {
            // Validate amount
            if ($data->amount < 3500) {
                http_response_code(400);
                echo json_encode(array("success" => false, "message" => "Minimum withdrawal is ₦3,500."));
                return;
            }

            if ($data->amount > $user['balance']) {
                http_response_code(400);
                echo json_encode(array("success" => false, "message" => "Insufficient balance."));
                return;
            }

            // Calculate fees and net amount
            $fee = $data->amount * 0.05; // 5% platform fee
            $net_amount = $data->amount - $fee;

            try {
                $db->beginTransaction();

                // Create withdrawal record
                $withdrawal_query = "INSERT INTO withdrawals (user_id, amount, fee, net_amount, payment_method, 
                                   bank_name, account_name, account_number, wallet_address, status) 
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')";
                $withdrawal_stmt = $db->prepare($withdrawal_query);
                $withdrawal_stmt->bindParam(1, $user['id']);
                $withdrawal_stmt->bindParam(2, $data->amount);
                $withdrawal_stmt->bindParam(3, $fee);
                $withdrawal_stmt->bindParam(4, $net_amount);
                $withdrawal_stmt->bindParam(5, $data->payment_method);
                $withdrawal_stmt->bindParam(6, $data->bank_name);
                $withdrawal_stmt->bindParam(7, $data->account_name);
                $withdrawal_stmt->bindParam(8, $data->account_number);
                $withdrawal_stmt->bindParam(9, $data->wallet_address);
                $withdrawal_stmt->execute();

                $withdrawal_id = $db->lastInsertId();

                // Deduct from user balance
                $update_balance = "UPDATE users SET balance = balance - ? WHERE id = ?";
                $balance_stmt = $db->prepare($update_balance);
                $balance_stmt->bindParam(1, $data->amount);
                $balance_stmt->bindParam(2, $user['id']);
                $balance_stmt->execute();

                $db->commit();

                echo json_encode(array(
                    "success" => true,
                    "message" => "Withdrawal request submitted successfully.",
                    "data" => array(
                        "withdrawal_id" => $withdrawal_id,
                        "fee" => $fee,
                        "net_amount" => $net_amount
                    )
                ));

            } catch (Exception $e) {
                $db->rollBack();
                http_response_code(503);
                echo json_encode(array("success" => false, "message" => "Unable to process withdrawal."));
            }
        } else {
            http_response_code(400);
            echo json_encode(array("success" => false, "message" => "Amount and payment method are required."));
        }
    }
}
?>

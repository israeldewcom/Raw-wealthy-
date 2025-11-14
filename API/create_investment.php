<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $auth->authenticate();
    if ($user) {
        $data = json_decode(file_get_contents("php://input"));

        if (!empty($data->plan_id) && !empty($data->amount)) {
            // Check if plan exists
            $plan_query = "SELECT * FROM investment_plans WHERE id = ?";
            $plan_stmt = $db->prepare($plan_query);
            $plan_stmt->bindParam(1, $data->plan_id);
            $plan_stmt->execute();

            if ($plan_stmt->rowCount() == 0) {
                http_response_code(404);
                echo json_encode(array("success" => false, "message" => "Investment plan not found."));
                return;
            }

            $plan = $plan_stmt->fetch(PDO::FETCH_ASSOC);

            // Check minimum amount
            if ($data->amount < $plan['min_amount']) {
                http_response_code(400);
                echo json_encode(array("success" => false, "message" => "Amount is below minimum investment for this plan."));
                return;
            }

            // Check user balance
            if ($data->amount > $user['balance']) {
                http_response_code(400);
                echo json_encode(array("success" => false, "message" => "Insufficient balance."));
                return;
            }

            try {
                $db->beginTransaction();

                // Create investment
                $investment_query = "INSERT INTO investments (user_id, plan_id, amount, auto_renew, status) 
                                    VALUES (?, ?, ?, ?, 'pending')";
                $investment_stmt = $db->prepare($investment_query);
                $investment_stmt->bindParam(1, $user['id']);
                $investment_stmt->bindParam(2, $data->plan_id);
                $investment_stmt->bindParam(3, $data->amount);
                $investment_stmt->bindParam(4, $data->auto_renew);
                $investment_stmt->execute();

                $investment_id = $db->lastInsertId();

                // Deduct from user balance
                $update_balance = "UPDATE users SET balance = balance - ? WHERE id = ?";
                $balance_stmt = $db->prepare($update_balance);
                $balance_stmt->bindParam(1, $data->amount);
                $balance_stmt->bindParam(2, $user['id']);
                $balance_stmt->execute();

                // Record transaction
                $transaction_query = "INSERT INTO transactions (user_id, type, amount, description) 
                                     VALUES (?, 'investment', ?, ?)";
                $transaction_stmt = $db->prepare($transaction_query);
                $description = "Investment in " . $plan['name'] . " plan";
                $transaction_stmt->bindParam(1, $user['id']);
                $transaction_stmt->bindParam(2, $data->amount);
                $transaction_stmt->bindParam(3, $description);
                $transaction_stmt->execute();

                $db->commit();

                echo json_encode(array(
                    "success" => true,
                    "message" => "Investment created successfully.",
                    "data" => array(
                        "investment_id" => $investment_id
                    )
                ));

            } catch (Exception $e) {
                $db->rollBack();
                http_response_code(503);
                echo json_encode(array("success" => false, "message" => "Unable to create investment."));
            }
        } else {
            http_response_code(400);
            echo json_encode(array("success" => false, "message" => "Plan ID and amount are required."));
        }
    }
}
?>

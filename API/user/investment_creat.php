<?php
require_once '../../models/Investment.php';
require_once '../../models/User.php';
require_once '../../utils/FileUpload.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $GLOBALS['user'];
    
    // Check if content type is multipart/form-data for file upload
    if (isset($_FILES['proof_image'])) {
        $data = $_POST;
        $file = $_FILES['proof_image'];
    } else {
        $data = json_decode(file_get_contents("php://input"), true);
        $file = null;
    }

    if (!empty($data['plan_id']) && !empty($data['amount'])) {
        $investment = new Investment($db);
        
        try {
            $investment->user_id = $user['id'];
            $investment->plan_id = $data['plan_id'];
            $investment->amount = $data['amount'];
            $investment->auto_renew = $data['auto_renew'] ?? false;

            // Handle file upload if present
            if ($file && $file['error'] === UPLOAD_ERR_OK) {
                $fileUpload = new FileUpload();
                $investment->proof_image = $fileUpload->uploadInvestmentProof($file, $user['id']);
            }

            $result = $investment->create();

            echo json_encode([
                "success" => true,
                "message" => "Investment created successfully.",
                "data" => [
                    "investment_id" => $result['investment_id'],
                    "daily_earnings" => $result['daily_earnings'],
                    "total_earnings" => $result['total_earnings']
                ]
            ]);

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
            "message" => "Plan ID and amount are required."
        ]);
    }
}
?>

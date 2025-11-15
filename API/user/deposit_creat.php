<?php
require_once '../../models/Deposit.php';
require_once '../../utils/FileUpload.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $GLOBALS['user'];
    
    // Handle multipart/form-data for file upload
    if (isset($_FILES['proof_image'])) {
        $data = $_POST;
        $file = $_FILES['proof_image'];
    } else {
        $data = json_decode(file_get_contents("php://input"), true);
        $file = null;
    }

    if (!empty($data['amount']) && !empty($data['payment_method'])) {
        $deposit = new Deposit($db);
        
        try {
            $deposit->user_id = $user['id'];
            $deposit->amount = $data['amount'];
            $deposit->payment_method = $data['payment_method'];
            $deposit->transaction_hash = $data['transaction_hash'] ?? null;

            // Handle file upload
            if ($file && $file['error'] === UPLOAD_ERR_OK) {
                $fileUpload = new FileUpload();
                $deposit->proof_image = $fileUpload->uploadDepositProof($file, $user['id']);
            }

            $deposit_id = $deposit->create();

            echo json_encode([
                "success" => true,
                "message" => "Deposit request submitted successfully.",
                "data" => [
                    "deposit_id" => $deposit_id
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
            "message" => "Amount and payment method are required."
        ]);
    }
}
?>

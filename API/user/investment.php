<?php
require_once '../../models/Investment.php';
require_once '../../models/User.php';

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $user = $GLOBALS['user'];
    
    $investment = new Investment($db);
    $investments = $investment->getUserInvestments($user['id']);

    echo json_encode([
        "success" => true,
        "data" => [
            "investments" => $investments
        ]
    ]);
}
?>

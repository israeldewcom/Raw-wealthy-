<?php
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $user = $auth->authenticate();
    if ($user) {
        // Get dashboard stats
        $user_model = new User($db);
        $stats = $user_model->getDashboardStats($user['id']);

        echo json_encode(array(
            "success" => true,
            "data" => array(
                "user" => $user,
                "dashboard_stats" => $stats
            )
        ));
    }
}
?>

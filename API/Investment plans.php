<?php
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $query = "SELECT * FROM investment_plans ORDER BY min_amount ASC";
    $stmt = $db->prepare($query);
    $stmt->execute();

    $plans = array();
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $plans[] = $row;
    }

    echo json_encode(array(
        "success" => true,
        "data" => array(
            "plans" => $plans
        )
    ));
}
?>

<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
echo json_encode([
    'status' => 'PHP is working!',
    'timestamp' => time(),
    'server' => 'Apache/PHP'
]);
?>

<?php
require_once 'config/config.php';

class JWT {
    private static function base64UrlEncode($data) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    private static function base64UrlDecode($data) {
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
    }

    public static function generateToken($user_id, $user_role = 'user') {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode([
            'user_id' => $user_id,
            'role' => $user_role,
            'iat' => time(),
            'exp' => time() + JWT_EXPIRE
        ]);

        $base64Header = self::base64UrlEncode($header);
        $base64Payload = self::base64UrlEncode($payload);

        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, JWT_SECRET, true);
        $base64Signature = self::base64UrlEncode($signature);

        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }

    public static function validateToken($token) {
        try {
            $tokenParts = explode('.', $token);
            if (count($tokenParts) != 3) {
                return false;
            }

            list($base64Header, $base64Payload, $base64Signature) = $tokenParts;

            $signature = self::base64UrlDecode($base64Signature);
            $expectedSignature = hash_hmac('sha256', $base64Header . "." . $base64Payload, JWT_SECRET, true);

            if (!hash_equals($expectedSignature, $signature)) {
                return false;
            }

            $payload = json_decode(self::base64UrlDecode($base64Payload), true);

            if ($payload['exp'] < time()) {
                return false;
            }

            return $payload;
        } catch (Exception $e) {
            error_log("JWT Validation Error: " . $e->getMessage());
            return false;
        }
    }

    public static function getUserIdFromToken($token) {
        $payload = self::validateToken($token);
        return $payload ? $payload['user_id'] : null;
    }
}
?>

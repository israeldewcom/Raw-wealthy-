<?php
require_once 'config/config.php';

class Email {
    private $smtp_host;
    private $smtp_port;
    private $smtp_user;
    private $smtp_pass;

    public function __construct() {
        $this->smtp_host = SMTP_HOST;
        $this->smtp_port = SMTP_PORT;
        $this->smtp_user = SMTP_USER;
        $this->smtp_pass = SMTP_PASS;
    }

    public function sendVerificationEmail($email, $name, $token) {
        $subject = "Verify Your Email - Raw Wealthy";
        $verification_url = "https://yourdomain.com/verify-email?token=" . $token;
        
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #10b981, #fbbf24); padding: 20px; text-align: center; color: white; }
                .content { padding: 20px; background: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; }
                .footer { padding: 20px; text-align: center; color: #666; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Raw Wealthy</h1>
                    <p>Investment Platform</p>
                </div>
                <div class='content'>
                    <h2>Hello {$name},</h2>
                    <p>Welcome to Raw Wealthy! Please verify your email address to complete your registration.</p>
                    <p style='text-align: center;'>
                        <a href='{$verification_url}' class='button'>Verify Email Address</a>
                    </p>
                    <p>If the button doesn't work, copy and paste this link in your browser:</p>
                    <p>{$verification_url}</p>
                </div>
                <div class='footer'>
                    <p>&copy; 2024 Raw Wealthy. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>";

        return $this->sendEmail($email, $subject, $message);
    }

    public function sendPasswordResetEmail($email, $name, $token) {
        $subject = "Reset Your Password - Raw Wealthy";
        $reset_url = "https://yourdomain.com/reset-password?token=" . $token;
        
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #0f172a; padding: 20px; text-align: center; color: white; }
                .content { padding: 20px; background: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background: #ef4444; color: white; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Password Reset</h1>
                </div>
                <div class='content'>
                    <h2>Hello {$name},</h2>
                    <p>You requested to reset your password. Click the button below to create a new password:</p>
                    <p style='text-align: center;'>
                        <a href='{$reset_url}' class='button'>Reset Password</a>
                    </p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this reset, please ignore this email.</p>
                </div>
            </div>
        </body>
        </html>";

        return $this->sendEmail($email, $subject, $message);
    }

    private function sendEmail($to, $subject, $message) {
        // For production, use PHPMailer or similar
        // This is a simplified version
        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        $headers .= "From: Raw Wealthy <noreply@rawwealthy.com>" . "\r\n";

        return mail($to, $subject, $message, $headers);
    }
}
?>

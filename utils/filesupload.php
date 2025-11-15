<?php
require_once 'config/config.php';

class FileUpload {
    private $allowed_types;
    private $max_size;

    public function __construct() {
        $this->allowed_types = ALLOWED_IMAGE_TYPES;
        $this->max_size = UPLOAD_MAX_SIZE;
    }

    public function uploadKYCFile($file, $user_id, $type) {
        return $this->uploadFile($file, 'kyc', $user_id, $type);
    }

    public function uploadDepositProof($file, $user_id) {
        return $this->uploadFile($file, 'deposits', $user_id, 'proof');
    }

    public function uploadInvestmentProof($file, $user_id) {
        return $this->uploadFile($file, 'investments', $user_id, 'proof');
    }

    private function uploadFile($file, $category, $user_id, $type) {
        try {
            // Check for upload errors
            if ($file['error'] !== UPLOAD_ERR_OK) {
                throw new Exception('File upload error: ' . $file['error']);
            }

            // Check file size
            if ($file['size'] > $this->max_size) {
                throw new Exception('File size exceeds maximum allowed size of 5MB');
            }

            // Get file extension
            $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            
            // Validate file type
            if (!in_array($file_extension, $this->allowed_types)) {
                throw new Exception('Invalid file type. Allowed types: ' . implode(', ', $this->allowed_types));
            }

            // Create upload directory if it doesn't exist
            $upload_dir = "../uploads/{$category}/{$user_id}/";
            if (!is_dir($upload_dir)) {
                mkdir($upload_dir, 0755, true);
            }

            // Generate unique filename
            $filename = $type . '_' . time() . '_' . uniqid() . '.' . $file_extension;
            $file_path = $upload_dir . $filename;

            // Move uploaded file
            if (!move_uploaded_file($file['tmp_name'], $file_path)) {
                throw new Exception('Failed to move uploaded file');
            }

            // Return relative path for database storage
            return "uploads/{$category}/{$user_id}/{$filename}";

        } catch (Exception $e) {
            error_log("File upload error: " . $e->getMessage());
            throw new Exception($e->getMessage());
        }
    }

    public function deleteFile($file_path) {
        $full_path = "../" . $file_path;
        if (file_exists($full_path)) {
            return unlink($full_path);
        }
        return false;
    }
}
?>

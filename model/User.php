<?php
class User {
    private $conn;
    private $table_name = "users";

    public $id;
    public $full_name;
    public $email;
    public $phone;
    public $password;
    public $referral_code;
    public $referred_by;
    public $risk_tolerance;
    public $investment_strategy;
    public $balance;
    public $total_earnings;
    public $referral_earnings;
    public $two_factor_enabled;
    public $two_factor_secret;
    public $kyc_verified;
    public $role;
    public $email_verified;
    public $email_verification_token;
    public $status;
    public $last_login;
    public $created_at;
    public $updated_at;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create() {
        $query = "INSERT INTO " . $this->table_name . " 
                SET full_name=:full_name, email=:email, phone=:phone, password=:password, 
                referral_code=:referral_code, referred_by=:referred_by, risk_tolerance=:risk_tolerance, 
                investment_strategy=:investment_strategy, email_verification_token=:email_verification_token";

        $stmt = $this->conn->prepare($query);

        $this->full_name = htmlspecialchars(strip_tags($this->full_name));
        $this->email = htmlspecialchars(strip_tags($this->email));
        $this->phone = htmlspecialchars(strip_tags($this->phone));
        $this->password = password_hash($this->password, PASSWORD_DEFAULT);
        $this->referral_code = $this->generateReferralCode();
        $this->referred_by = htmlspecialchars(strip_tags($this->referred_by));
        $this->risk_tolerance = htmlspecialchars(strip_tags($this->risk_tolerance));
        $this->investment_strategy = htmlspecialchars(strip_tags($this->investment_strategy));
        $this->email_verification_token = bin2hex(random_bytes(50));

        $stmt->bindParam(":full_name", $this->full_name);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":phone", $this->phone);
        $stmt->bindParam(":password", $this->password);
        $stmt->bindParam(":referral_code", $this->referral_code);
        $stmt->bindParam(":referred_by", $this->referred_by);
        $stmt->bindParam(":risk_tolerance", $this->risk_tolerance);
        $stmt->bindParam(":investment_strategy", $this->investment_strategy);
        $stmt->bindParam(":email_verification_token", $this->email_verification_token);

        if($stmt->execute()) {
            $this->id = $this->conn->lastInsertId();
            return true;
        }
        return false;
    }

    public function emailExists() {
        $query = "SELECT id, full_name, password, role, balance, kyc_verified, referral_code, 
                         status, two_factor_enabled, two_factor_secret 
                FROM " . $this->table_name . " 
                WHERE email = ? 
                LIMIT 0,1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->email);
        $stmt->execute();

        if($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->id = $row['id'];
            $this->full_name = $row['full_name'];
            $this->password = $row['password'];
            $this->role = $row['role'];
            $this->balance = $row['balance'];
            $this->kyc_verified = $row['kyc_verified'];
            $this->referral_code = $row['referral_code'];
            $this->status = $row['status'];
            $this->two_factor_enabled = $row['two_factor_enabled'];
            $this->two_factor_secret = $row['two_factor_secret'];
            return true;
        }
        return false;
    }

    public function getUserProfile() {
        $query = "SELECT id, full_name, email, phone, balance, total_earnings, referral_earnings, 
                         kyc_verified, role, referral_code, risk_tolerance, investment_strategy,
                         email_verified, status, created_at
                  FROM " . $this->table_name . " 
                  WHERE id = ?";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updateLastLogin() {
        $query = "UPDATE " . $this->table_name . " SET last_login = NOW() WHERE id = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->id);
        return $stmt->execute();
    }

    public function getDashboardStats($user_id) {
        $query = "SELECT 
                    (SELECT COALESCE(SUM(amount), 0) FROM investments WHERE user_id = ? AND status = 'active') as active_investment_value,
                    (SELECT COALESCE(SUM(total_earnings), 0) FROM investments WHERE user_id = ?) as total_investment_earnings,
                    (SELECT COUNT(*) FROM investments WHERE user_id = ? AND status = 'active') as active_investments_count,
                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = ?) as total_referrals,
                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND status = 'approved') as active_referrals";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $user_id);
        $stmt->bindParam(2, $user_id);
        $stmt->bindParam(3, $user_id);
        $stmt->bindParam(4, $user_id);
        $stmt->bindParam(5, $user_id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function generateReferralCode() {
        return strtoupper(substr(md5(uniqid()), 0, 8));
    }

    // Add more methods for profile updates, password changes, etc.
}
?>

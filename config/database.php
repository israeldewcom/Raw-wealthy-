// Update config/database.php with better error handling
public function getConnection() {
    $this->conn = null;
    try {
        $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
        $this->conn->exec("set names utf8");
        $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        
        error_log("Database connected successfully");
        return $this->conn;
    } catch(PDOException $exception) {
        error_log("Database connection failed: " . $exception->getMessage());
        error_log("Connection details: host=" . $this->host . ", db=" . $this->db_name . ", user=" . $this->username);
        throw new Exception("Database connection failed: " . $exception->getMessage());
    }
}

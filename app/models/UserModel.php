<?php
require_once ROOT_PATH . "/app/config/database.php";

class UserModel
{
    private PDO $conn;
    private string $table;

    public function __construct(string $userType)
    {
        $db = new Database();
        $this->conn = $db->connect();

        // اختيار الجدول بناءً على نوع المستخدم
        $this->table = match ($userType) {
            'customer' => 'customers',
            'merchant' => 'merchants',
            'admin' => 'admins',
            default => throw new Exception("Invalid user type: $userType"),
        };
    }

    // =========================
    // تسجيل مستخدم جديد
    // =========================
    public function register(string $name, string $email, string $password): bool
    {
        try {
            // تحقق إذا البريد موجود بالفعل
            $check = $this->conn->prepare("SELECT 1 FROM {$this->table} WHERE email = :email LIMIT 1");
            $check->execute([":email" => $email]);
            if ($check->fetch()) {
                return false; // البريد موجود بالفعل
            }

            $hash = password_hash($password, PASSWORD_DEFAULT);

            $query = "INSERT INTO {$this->table} (name, email, password_hash)
                      VALUES (:name, :email, :password_hash)";
            $stmt = $this->conn->prepare($query);

            return $stmt->execute([
                ":name" => htmlspecialchars($name),
                ":email" => htmlspecialchars($email),
                ":password_hash" => $hash,
            ]);
        } catch (PDOException $e) {
            return false;
        }
    }

    // =========================
    // تسجيل الدخول
    // =========================
    public function login(string $email, string $password)
    {
        try {
            $query = "SELECT * FROM {$this->table} WHERE email = :email LIMIT 1";
            $stmt = $this->conn->prepare($query);
            $stmt->execute([":email" => $email]);

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password_hash'])) {
                return $user;
            }

            return false;
        } catch (PDOException $e) {
            return false;
        }
    }

    // =========================
    // دالة عامة لتحديث أي مستخدم
    // =========================
    private function updateUser(int $id, array $data, string $idField): bool
    {
        $fields = [];
        $params = [":id" => $id];

        foreach ($data as $key => $value) {
            if ($key === 'password' && $value !== null && $value !== '') {
                $fields[] = "password_hash = :password_hash";
                $params[':password_hash'] = password_hash($value, PASSWORD_DEFAULT);
            } else {
                $fields[] = "$key = :$key";
                $params[":$key"] = htmlspecialchars($value);
            }
        }

        $sql = "UPDATE {$this->table} SET " . implode(", ", $fields) . " WHERE $idField = :id";
        $stmt = $this->conn->prepare($sql);
        return $stmt->execute($params);
    }

    // =========================
    // تحديث بيانات العملاء
    // =========================
    public function updateCustomer(int $customerId, string $name, string $email, ?string $password = null): bool
    {
        if ($this->table !== 'customers') {
            throw new Exception("updateCustomer can only be used with customers table.");
        }

        return $this->updateUser($customerId, [
            'name' => $name,
            'email' => $email,
            'password' => $password
        ], 'customer_id');
    }

    // =========================
    // تحديث بيانات التجار
    // =========================
    public function updateMerchant(int $merchantId, string $name, string $email, ?string $password = null): bool
    {
        if ($this->table !== 'merchants') {
            throw new Exception("updateMerchant can only be used with merchants table.");
        }

        return $this->updateUser($merchantId, [
            'name' => $name,
            'email' => $email,
            'password' => $password
        ], 'merchant_id');
    }
}

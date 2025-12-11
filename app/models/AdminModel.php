<?php

require_once ROOT_PATH . "/app/config/database.php";

class AdminModel
{
    private $conn;

    public function __construct()
    {
        $db = new Database();
        $this->conn = $db->connect();
    }

    // ============================
    // LOGIN ADMIN
    // ============================
    public function login($email, $password)
    {
        $stmt = $this->conn->prepare("SELECT * FROM admins WHERE email = :email LIMIT 1");
        $stmt->execute([":email" => $email]);

        $admin = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($admin && password_verify($password, $admin["password_hash"])) {
            return $admin;
        }

        return false;
    }

    // ============================
    // COUNT TABLE ROWS
    // ============================
    public function countTable($table)
    {
        $stmt = $this->conn->prepare("SELECT COUNT(*) FROM $table");
        $stmt->execute();
        return $stmt->fetchColumn();
    }

    // ============================
    // GET ALL CUSTOMERS
    // ============================
    public function getAllCustomers()
    {
        $stmt = $this->conn->query("SELECT * FROM customers ORDER BY customer_id DESC");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // ============================
    // GET ALL MERCHANTS
    // ============================
    public function getAllMerchants()
    {
        $stmt = $this->conn->query("SELECT * FROM merchants ORDER BY merchant_id DESC");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // ============================
    // GET ALL SUBSCRIPTIONS (with join)
    // ============================
    public function getAllSubscriptions()
    {
        $query = "
            SELECT s.*, 
                   c.name AS customer_name, 
                   m.name AS merchant_name
            FROM subscriptions s
            LEFT JOIN customers c ON s.customer_id = c.customer_id
            LEFT JOIN merchants m ON s.merchant_id = m.merchant_id
            ORDER BY s.subscription_id DESC
        ";

        $stmt = $this->conn->query($query);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // ============================
    // DELETE RECORD BY ID
    // ============================
    public function deleteById(string $table, string $idColumn, int $id)
    {
        // حماية ضد SQL Injection
        $allowedTables = ['customers', 'merchants', 'offers', 'customer_offers', 'subscriptions'];
        $allowedColumns = ['customer_id', 'merchant_id', 'offer_id', 'subscription_id'];

        if (!in_array($table, $allowedTables) || !in_array($idColumn, $allowedColumns)) {
            throw new Exception("Invalid table or column");
        }

        try {
            $this->conn->beginTransaction();

            // حذف سجلات مرتبطة إذا كان العملاء
            if ($table === 'customers') {
                // حذف customer_offers المرتبطة
                $stmt = $this->conn->prepare("DELETE FROM customer_offers WHERE customer_id = :id");
                $stmt->execute([':id' => $id]);

                // حذف subscriptions المرتبطة
                $stmt = $this->conn->prepare("DELETE FROM subscriptions WHERE customer_id = :id");
                $stmt->execute([':id' => $id]);
            }

            // حذف سجلات مرتبطة إذا كان التاجر
            if ($table === 'merchants') {
                // حذف customer_offers المرتبطة بالعروض
                $stmt = $this->conn->prepare("
                    DELETE co FROM customer_offers co
                    INNER JOIN offers o ON co.offer_id = o.offer_id
                    WHERE o.merchant_id = :id
                ");
                $stmt->execute([':id' => $id]);

                // حذف العروض المرتبطة بالتاجر
                $stmt = $this->conn->prepare("DELETE FROM offers WHERE merchant_id = :id");
                $stmt->execute([':id' => $id]);
            }

            // حذف السجل الرئيسي
            $stmt = $this->conn->prepare("DELETE FROM $table WHERE $idColumn = :id");
            $stmt->execute([':id' => $id]);

            $this->conn->commit();
            return true;

        } catch (PDOException $e) {
            $this->conn->rollBack();
            throw $e;
        }
    }
}

<?php

require_once ROOT_PATH . "/app/config/database.php";

class MerchantModel
{
    private PDO $conn;

    public function __construct()
    {
        $db = new Database();
        $this->conn = $db->connect();
    }

    // =========================
    // حساب النقاط تلقائياً
    // =========================
    public function calculatePoints($amount, $rate = 1): int
    {
        // كل 1 جنيه = $rate نقطة (افتراضي 1)
        return intval($amount * $rate);
    }

    // =========================
    // إضافة النقاط للعميل
    // =========================
    public function addPoints(string $email, int $points): bool
    {
        // التأكد من وجود العميل
        $check = $this->conn->prepare("SELECT customer_id FROM customers WHERE email = :email LIMIT 1");
        $check->execute([":email" => $email]);
        $customer = $check->fetch(PDO::FETCH_ASSOC);

        if (!$customer) {
            return false; // العميل غير موجود
        }

        // إضافة النقاط باستخدام customer_id
        $stmt = $this->conn->prepare("
            UPDATE customers
            SET points = points + :points
            WHERE customer_id = :id
        ");

        return $stmt->execute([
            ":points" => $points,
            ":id" => $customer['customer_id']
        ]);
    }

    // =========================
    // الحصول على رصيد نقاط العميل
    // =========================
    public function getPoints(string $email): int
    {
        $stmt = $this->conn->prepare("SELECT points FROM customers WHERE email = :email LIMIT 1");
        $stmt->execute([":email" => $email]);
        $points = $stmt->fetchColumn();
        return $points !== false ? (int) $points : 0;
    }
}

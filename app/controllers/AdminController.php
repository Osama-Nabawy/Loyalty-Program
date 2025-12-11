<?php

require_once ROOT_PATH . "/app/models/AdminModel.php";

class AdminController
{
    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    // ============================
    // LOGIN ADMIN
    // ============================
    public function login()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            $email = $_POST['email'] ?? '';
            $password = $_POST['password'] ?? '';

            $model = new AdminModel();
            $admin = $model->login($email, $password);

            if ($admin) {
                $_SESSION['admin'] = $admin;
                header("Location: /Test_project/public/admins/dashboard");
                exit;
            }

            echo "Invalid admin credentials!";
        } else {
            require ROOT_PATH . "/app/views/admins/login.php";
        }
    }

    // ============================
    // DASHBOARD
    // ============================
    public function dashboard()
    {
        if (!isset($_SESSION['admin'])) {
            header("Location: /Test_project/public/admins/login");
            exit;
        }

        $model = new AdminModel();

        $customerCount = $model->countTable("customers");
        $merchantCount = $model->countTable("merchants");
        $subscriptionCount = $model->countTable("subscriptions");

        require ROOT_PATH . "/app/views/admins/dashboard.php";
    }

    // ============================
    // VIEW CUSTOMERS
    // ============================
    public function viewCustomers()
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();
        $customers = $model->getAllCustomers();

        require ROOT_PATH . "/app/views/admins/view_customers.php";
    }

    // ============================
    // VIEW MERCHANTS
    // ============================
    public function viewMerchants()
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();
        $merchants = $model->getAllMerchants();

        require ROOT_PATH . "/app/views/admins/view_merchants.php";
    }

    // ============================
    // VIEW SUBSCRIPTIONS
    // ============================
    public function viewSubscriptions()
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();
        $subscriptions = $model->getAllSubscriptions();

        require ROOT_PATH . "/app/views/admins/view_subscriptions.php";
    }

    // ============================
    // DELETE CUSTOMER
    // ============================
    public function deleteCustomer($id)
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();

        if ($model->deleteById("customers", "customer_id", $id)) {
            // تخزين رسالة النجاح في الجلسة
            $_SESSION['success'] = "Customer deleted successfully!";
            // إعادة التوجيه إلى صفحة عرض العملاء
            header("Location: /Test_project/public/admins/view_customers");
            exit;
        } else {
            echo "Failed to delete customer!";
        }
    }

    // ============================
    // DELETE MERCHANT
    // ============================
    public function deleteMerchant($id)
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();

        if ($model->deleteById("merchants", "merchant_id", $id)) {
            // تخزين رسالة النجاح في الجلسة
            $_SESSION['success'] = "Merchant deleted successfully!";
            // إعادة التوجيه إلى صفحة عرض التجار
            header("Location: /Test_project/public/admins/view_merchants");
            exit;
        } else {
            echo "Failed to delete merchant!";
        }
    }

// ============================
// DELETE SUBSCRIPTION
// ============================
    public function deleteSubscription($id)
    {
        if (!isset($_SESSION['admin'])) {
            echo "Not authorized!";
            return;
        }

        $model = new AdminModel();

        if ($model->deleteById("subscriptions", "subscription_id", $id)) {
            $_SESSION['success'] = "Subscription deleted successfully!";
        } else {
            $_SESSION['error'] = "Failed to delete subscription!";
        }

        // إعادة التوجيه للصفحة الصحيحة
        header("Location: /Test_project/public/admins/view_subscriptions");
        exit;
    }


}

<?php

require_once ROOT_PATH . "/app/models/UserModel.php";
require_once ROOT_PATH . "/app/models/OfferModel.php";
require_once ROOT_PATH . "/app/models/SubscriptionModel.php";

class UserController
{
    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /* =========================
       SELECT USER TYPE
    ========================== */
    public function selectUserType()
    {
        // لو جاية POST → اختار وودّي على صفحة التسجيل المناسبة
        if ($_SERVER["REQUEST_METHOD"] === "POST") {

            $type = $_POST["user_type"] ?? "customer";

            if ($type === "merchant") {
                header("Location: /Test_project/public/register-merchant");
            } else {
                header("Location: /Test_project/public/register-customer");
            }
            exit;
        }

        // GET → اعرض صفحة اختيار النوع
        require ROOT_PATH . "/app/views/users/select_type.php";
    }

    // لو الرواتر بيستدعي handleUserType خليه يستخدم نفس المنطق
    public function handleUserType()
    {
        $this->selectUserType();
    }

    /* =========================
       REGISTER CUSTOMER
    ========================== */
    public function registerCustomer()
    {
        if ($_SERVER["REQUEST_METHOD"] === "POST") {

            $name     = trim($_POST["name"]     ?? "");
            $email    = trim($_POST["email"]    ?? "");
            $password = $_POST["password"]      ?? "";

            if (!$name || !$email || !$password) {
                $error = "All fields are required.";
                require ROOT_PATH . "/app/views/users/register_customer.php";
                return;
            }

            $model = new UserModel("customer");
            $ok    = $model->register($name, $email, $password);

            if ($ok) {
                // بعد التسجيل وديه صفحة اللوجين
                header("Location: /Test_project/public/login");
                exit;
            } else {
                $error = "Customer registration failed (email may already exist).";
                require ROOT_PATH . "/app/views/users/register_customer.php";
                return;
            }
        }

        // GET
        require ROOT_PATH . "/app/views/users/register_customer.php";
    }

    /* =========================
       REGISTER MERCHANT
    ========================== */
    public function registerMerchant()
    {
        if ($_SERVER["REQUEST_METHOD"] === "POST") {

            $name     = trim($_POST["name"]     ?? "");
            $email    = trim($_POST["email"]    ?? "");
            $password = $_POST["password"]      ?? "";

            if (!$name || !$email || !$password) {
                $error = "All fields are required.";
                require ROOT_PATH . "/app/views/users/register_merchant.php";
                return;
            }

            $model = new UserModel("merchant");
            $ok    = $model->register($name, $email, $password);

            if ($ok) {
                header("Location: /Test_project/public/login");
                exit;
            } else {
                $error = "Merchant registration failed (email may already exist).";
                require ROOT_PATH . "/app/views/users/register_merchant.php";
                return;
            }
        }

        // GET
        require ROOT_PATH . "/app/views/users/register_merchant.php";
    }

    /* =========================
       LOGIN
    ========================== */
    public function login()
    {
        if ($_SERVER["REQUEST_METHOD"] === "POST") {

            $email    = $_POST["email"]    ?? "";
            $password = $_POST["password"] ?? "";
            $error    = null;

            // Try Customer
            $customerModel = new UserModel("customer");
            $customer      = $customerModel->login($email, $password);

            if ($customer) {
                $_SESSION["user"] = [
                    "customer_id" => $customer["customer_id"],
                    "name"        => $customer["name"],
                    "email"       => $customer["email"]
                ];
                $_SESSION["role"] = "customer";

                header("Location: /Test_project/public/customer/dashboard");
                exit;
            }

            // Try Merchant
            $merchantModel = new UserModel("merchant");
            $merchant      = $merchantModel->login($email, $password);

            if ($merchant) {
                $_SESSION["user"] = [
                    "merchant_id" => $merchant["merchant_id"],
                    "name"        => $merchant["name"],
                    "email"       => $merchant["email"]
                ];
                $_SESSION["role"] = "merchant";

                header("Location: /Test_project/public/merchant/dashboard");
                exit;
            }

            $error = "Incorrect email or password.";
            require ROOT_PATH . "/app/views/users/login.php";
            return;
        }

        require ROOT_PATH . "/app/views/users/login.php";
    }

    /* =========================
       LOGOUT
    ========================== */
    public function logout()
    {
        session_destroy();
        header("Location: /Test_project/public/");
        exit;
    }

    /* =========================
       REDEEM PAGE (SHOW ONLY)
    ========================== */
    public function redeemOffer()
    {
        if (!isset($_SESSION["role"]) || $_SESSION["role"] !== "customer") {
            header("Location: /Test_project/public/login");
            exit;
        }

        if (!isset($_GET["id"])) {
            die("Offer ID missing");
        }

        $offerId    = (int)$_GET["id"];
        $customerId = (int)$_SESSION["user"]["customer_id"];

        $offerModel = new OfferModel();
        $subModel   = new SubscriptionModel();

        // Fetch offer
        $offer = $offerModel->getOfferById($offerId);

        if (!$offer) {
            die("Offer not found.");
        }

        // Subscription tier
        $subscription = $subModel->getSubscriptionByCustomerId($customerId);

        $extra = 0;
        if ($subscription) {
            switch ($subscription["tier"]) {
                case "silver":   $extra = 20; break;
                case "gold":     $extra = 30; break;
                case "platinum": $extra = 40; break;
            }
        }

        $merchantDiscount = floatval($offer["discount_value"]);
        $finalDiscount    = $merchantDiscount + $extra;

        $offer["final_discount"] = $finalDiscount;

        require ROOT_PATH . "/app/views/users/receipt.php";
    }

    /* =========================
       CONFIRM REDEEM (SAVE TO DB)
    ========================== */
    public function confirmRedeem()
    {
        if (!isset($_SESSION["user"]) || $_SESSION["role"] !== "customer") {
            header("Location: /Test_project/public/login");
            exit;
        }

        if ($_SERVER["REQUEST_METHOD"] !== "POST" || !isset($_POST["offer_id"])) {
            die("Invalid access");
        }

        $offerId    = (int)$_POST["offer_id"];
        $customerId = (int)$_SESSION["user"]["customer_id"];

        $offerModel = new OfferModel();
        $saved      = $offerModel->logRedeem($customerId, $offerId);

        if ($saved) {
            $_SESSION["redeem_success"] = "Offer saved successfully!";
        } else {
            $_SESSION["redeem_error"] = "Failed to save offer.";
        }

        header("Location: /Test_project/public/customer/redeem-offer?id=" . $offerId);
        exit;
    }

    /* =========================
       CUSTOMER DASHBOARD
    ========================== */
    public function customerDashboard()
    {
        if (!isset($_SESSION["user"]) || $_SESSION["role"] !== "customer") {
            header("Location: /Test_project/public/login");
            exit;
        }

        require ROOT_PATH . "/app/views/users/customer_dashboard.php";
    }

    /* =========================
       VIEW REDEEMED OFFERS
    ========================== */
    public function redeemedOffers()
    {
        if (!isset($_SESSION["user"]) || $_SESSION["role"] !== "customer") {
            header("Location: /Test_project/public/login");
            exit;
        }

        $customerId = $_SESSION["user"]["customer_id"];
        $offers     = (new OfferModel())->getCustomerRedeemedOffers($customerId);

        require ROOT_PATH . "/app/views/users/redeemed_offers.php";
    }

    /* =========================
       VIEW ALL OFFERS
    ========================== */
    public function viewOffers()
    {
        $offerModel = new OfferModel();
        $offers     = $offerModel->getAllOffers();

        $isCustomer = isset($_SESSION["role"]) && $_SESSION["role"] === "customer";

        require ROOT_PATH . "/app/views/users/offers_list.php";
    }

    /* =========================
       CUSTOMER PROFILE (EDIT)
    ========================== */
    public function customerProfile()
    {
        if (!isset($_SESSION["user"]) || $_SESSION["role"] !== "customer") {
            header("Location: /Test_project/public/login");
            exit;
        }

        $model    = new UserModel("customer");
        $customer = $_SESSION["user"];

        if ($_SERVER["REQUEST_METHOD"] === "POST") {

            $name     = $_POST["name"]     ?? "";
            $email    = $_POST["email"]    ?? "";
            $password = $_POST["password"] ?? "";

            if (!$name || !$email) {
                $error = "Name and Email cannot be empty!";
                require ROOT_PATH . "/app/views/users/customer_profile.php";
                return;
            }

            $passwordToSave = $password !== "" ? $password : null;

            $updated = $model->updateCustomer(
                $customer["customer_id"],
                $name,
                $email,
                $passwordToSave
            );

            if ($updated) {
                $_SESSION["user"]["name"]  = $name;
                $_SESSION["user"]["email"] = $email;
                $success = "Profile updated successfully!";
            } else {
                $error = "Update failed!";
            }

            require ROOT_PATH . "/app/views/users/customer_profile.php";
            return;
        }

        require ROOT_PATH . "/app/views/users/customer_profile.php";
    }
}

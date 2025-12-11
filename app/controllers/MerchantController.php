<?php

require_once ROOT_PATH . "/app/models/MerchantModel.php";
require_once ROOT_PATH . "/app/models/UserModel.php";

class MerchantController
{
    private MerchantModel $merchantModel;

    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->merchantModel = new MerchantModel();
    }

    // =========================
    // Authorization check
    // =========================
    private function authorizeMerchant()
    {
        if (!isset($_SESSION['user']) || $_SESSION['role'] !== 'merchant') {
            header("Location: /Test_project/public/login");
            exit;
        }
    }

    // =========================
    // Dashboard
    // =========================
    public function dashboard()
    {
        $this->authorizeMerchant();
        require ROOT_PATH . "/app/views/merchants/dashboard.php";
    }

    // =========================
    // Purchase points
    // =========================
    public function purchase()
    {
        $this->authorizeMerchant();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            $email = filter_var(trim($_POST['customer_email']), FILTER_VALIDATE_EMAIL);
            $amount = (float) ($_POST['amount'] ?? 0);

            if (!$email || $amount <= 0) {
                $_SESSION['flash'] = "Invalid email or amount!";
                header("Location: /Test_project/public/merchant/purchase");
                exit;
            }

            $points = $this->merchantModel->calculatePoints($amount);
            $success = $this->merchantModel->addPoints($email, $points);

            $_SESSION['flash'] = $success
                ? "Purchase recorded. Added $points points automatically!"
                : "Failed to add points. Customer not found.";

            header("Location: /Test_project/public/merchant/purchase");
            exit;

        } else {
            require ROOT_PATH . "/app/views/merchants/purchase.php";
        }
    }

    // =========================
    // Show create offer form
    // =========================
    public function offers()
    {
        $this->authorizeMerchant();
        require ROOT_PATH . "/app/views/merchants/create_offer.php";
    }

    // =========================
    // Create offer
    // =========================
    public function createOffer()
    {
        $this->authorizeMerchant();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            require_once ROOT_PATH . "/app/models/OfferModel.php";
            $model = new OfferModel();

            $title = trim($_POST['title'] ?? '');
            $description = trim($_POST['description'] ?? '');
            $discount = (float) ($_POST['discount_value'] ?? 0);

            if (!$title || !$description || $discount <= 0) {
                $_SESSION['flash'] = "All fields are required and discount must be > 0!";
                header("Location: /Test_project/public/merchant/offers");
                exit;
            }

            $success = $model->createOffer($_SESSION['user']['merchant_id'], $title, $description, $discount);

            $_SESSION['flash'] = $success ? "Offer created successfully!" : "Failed to create offer!";
            header("Location: /Test_project/public/merchant/offers");
            exit;
        }

        require ROOT_PATH . "/app/views/merchants/create_offer.php";
    }

    // =========================
    // Edit offers list
    // =========================
    public function editOffers()
    {
        $this->authorizeMerchant();

        require_once ROOT_PATH . "/app/models/OfferModel.php";
        $model = new OfferModel();

        $offers = $model->getOffersByMerchant($_SESSION['user']['merchant_id']) ?? [];

        require ROOT_PATH . "/app/views/merchants/edit_offers.php";
    }

    // =========================
    // Edit single offer
    // =========================
    public function editOfferById($id)
    {
        $this->authorizeMerchant();

        require_once ROOT_PATH . "/app/models/OfferModel.php";
        $model = new OfferModel();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            $title = trim($_POST['title'] ?? '');
            $description = trim($_POST['description'] ?? '');
            $discount = (float) ($_POST['discount_value'] ?? 0);

            if (!$title || !$description || $discount <= 0) {
                $_SESSION['flash'] = "All fields are required and discount must be > 0!";
                header("Location: /Test_project/public/merchant/offers/edit-list");
                exit;
            }

            $success = $model->updateOffer($id, $title, $description, $discount);

            $_SESSION['flash'] = $success ? "Offer updated successfully!" : "Failed to update offer!";
            header("Location: /Test_project/public/merchant/offers/edit-list");
            exit;
        }

        $offer = $model->getOfferById($id) ?? null;
        require ROOT_PATH . "/app/views/merchants/edit_offers.php";
    }

    // =========================
    // Delete offers list
    // =========================
    public function deleteOffers()
    {
        $this->authorizeMerchant();

        require_once ROOT_PATH . "/app/models/OfferModel.php";
        $model = new OfferModel();

        $offers = $model->getOffersByMerchant($_SESSION['user']['merchant_id']) ?? [];
        require ROOT_PATH . "/app/views/merchants/delete_offers.php";
    }

    // =========================
    // Delete single offer
    // =========================
    public function deleteOfferById($id)
    {
        $this->authorizeMerchant();

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("Location: /Test_project/public/merchant/offers");
            exit;
        }

        require_once ROOT_PATH . "/app/models/OfferModel.php";
        $model = new OfferModel();

        $success = $model->deleteOffer($id);
        $_SESSION['flash'] = $success ? "Offer deleted successfully!" : "Failed to delete offer!";

        header("Location: /Test_project/public/merchant/offers");
        exit;
    }

    // =========================
    // Merchant profile
    // =========================
    public function profile()
    {
        $this->authorizeMerchant();

        $merchant = $_SESSION['user'];

        require_once ROOT_PATH . "/app/models/UserModel.php";
        $userModel = new UserModel('merchant'); // ✅ تأكدنا أن النوع merchant

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $name = trim($_POST['name'] ?? '');
            $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
            $password = $_POST['password'] ?? null;

            if (!$name || !$email) {
                $_SESSION['flash'] = "Name and email are required!";
                header("Location: /Test_project/public/merchant/profile");
                exit;
            }

            $userModel->updateMerchant($merchant['merchant_id'], $name, $email, $password ?: null);

            $_SESSION['user']['name'] = $name;
            $_SESSION['user']['email'] = $email;

            $_SESSION['flash'] = "Profile updated successfully!";
            header("Location: /Test_project/public/merchant/profile");
            exit;
        }

        require ROOT_PATH . "/app/views/merchants/profile.php";
    }

    // =========================
    // My offers page
    // =========================
    public function myOffers()
    {
        $this->authorizeMerchant();

        require_once ROOT_PATH . "/app/models/OfferModel.php";
        $model = new OfferModel();

        $merchantId = (int) $_SESSION['user']['merchant_id'];
        $offers = $model->getOffersByMerchant($merchantId) ?? [];

        require ROOT_PATH . "/app/views/merchants/my_offers.php";
    }
}

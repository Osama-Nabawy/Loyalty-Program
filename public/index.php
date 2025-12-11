<?php
declare(strict_types=1);

define("ROOT_PATH", dirname(__DIR__));

// Load Config + Core
require ROOT_PATH . "/app/config/database.php";
require ROOT_PATH . "/app/core/Router.php";

// Load Controllers
require ROOT_PATH . "/app/controllers/UserController.php";
require ROOT_PATH . "/app/controllers/SubscriptionController.php";
require ROOT_PATH . "/app/controllers/AdminController.php";
require ROOT_PATH . "/app/controllers/MerchantController.php";

$router = new Router();

/* ------------------ Home ------------------ */
$router->add("/", function () {
    require ROOT_PATH . "/app/views/home.php";
});

/* ------------------ User Authentication ------------------ */
$router->add("/select-user-type", fn() => (new UserController())->selectUserType());
$router->add("/register-customer", fn() => (new UserController())->registerCustomer());
$router->add("/register-merchant", fn() => (new UserController())->registerMerchant());
$router->add("/login", fn() => (new UserController())->login());
$router->add("/logout", fn() => (new UserController())->logout());

$router->add("/register", function () {
    header("Location: /Test_project/public/select-user-type");
    exit;
});

/* ------------------ Subscriptions ------------------ */
$router->add("/subscription/join", fn() => (new SubscriptionController())->join());
$router->add("/subscription/points", fn() => require ROOT_PATH . "/app/views/subscriptions/points.php");
$router->add("/subscription/value", fn() => require ROOT_PATH . "/app/views/subscriptions/value.php");

$router->add("/subscription/cancel", function () {
    if (!isset($_GET['id']))
        return print ("Missing subscription ID");
    (new SubscriptionController())->cancel($_GET['id']);
});

$router->add("/subscription/mine", function () {
    if (!isset($_GET['customer_id']))
        return print ("Missing customer ID");
    (new SubscriptionController())->mySubscriptions($_GET['customer_id']);
});

/* ------------------ Admin ------------------ */
$router->add("/admins/login", fn() => (new AdminController())->login());
$router->add("/admins/dashboard", fn() => (new AdminController())->dashboard());

$router->add("/admins/view_customers", fn() => (new AdminController())->viewCustomers());
$router->add("/admins/view_merchants", fn() => (new AdminController())->viewMerchants());
$router->add("/admins/view_subscriptions", fn() => (new AdminController())->viewSubscriptions());

/* ---- DELETE ROUTES ---- */
$router->add("/admins/deleteCustomer", function () {
    if (!isset($_GET['id']))
        return print ("Missing Customer ID");
    (new AdminController())->deleteCustomer((int) $_GET['id']);
});

$router->add("/admins/deleteMerchant", function () {
    if (!isset($_GET['id']))
        return print ("Missing Merchant ID");
    (new AdminController())->deleteMerchant((int) $_GET['id']);
});

// ====== NEW: DELETE SUBSCRIPTION ======
$router->add("/admins/deleteSubscription", function () {
    if (!isset($_GET['id']))
        return print ("Missing Subscription ID");
    (new AdminController())->deleteSubscription((int) $_GET['id']);
});

/* ------------------ Merchant ------------------ */
$router->add("/merchant/dashboard", fn() => (new MerchantController())->dashboard());
$router->add("/merchant/purchase", fn() => (new MerchantController())->purchase());

/* ------------------ Customer ------------------ */
$router->add("/customer/redeem-offer", fn() => (new UserController())->redeemOffer());
$router->add("/customer/redeemed-offers", fn() => (new UserController())->redeemedOffers());

/* ------------------ Merchant Offers ------------------ */
$router->add("/merchant/offers", fn() => (new MerchantController())->offers());
$router->add("/merchant/offers/create", fn() => (new MerchantController())->createOffer());
$router->add("/merchant/offers/edit-list", fn() => (new MerchantController())->editOffers());
$router->add("/merchant/offers/delete-list", fn() => (new MerchantController())->deleteOffers());

$router->add("/merchant/offers/edit", function () {
    if (!isset($_GET['id']))
        return print ("Missing Offer ID");
    (new MerchantController())->editOfferById((int) $_GET['id']);
});

$router->add("/merchant/offers/delete", function () {
    if (!isset($_GET['id']))
        return print ("Missing Offer ID");
    (new MerchantController())->deleteOfferById((int) $_GET['id']);
});

$router->add("/merchant/profile", fn() => (new MerchantController())->profile());
$router->add("/merchant/my-offers", fn() => (new MerchantController())->myOffers());

/* ------------------ Customer Dashboard & Profile ------------------ */
$router->add("/customer/dashboard", fn() => (new UserController())->customerDashboard());
$router->add("/customer/profile", fn() => (new UserController())->customerProfile());
$router->add("/customer/redeemed-offers", fn() => (new UserController())->redeemedOffers());

$router->add("/offers", fn() => (new UserController())->viewOffers());

$router->add("/customer/confirm-redeem", function () {
    (new UserController())->confirmRedeem();
});

/* ------------------ Path Handling ------------------ */
$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

// PROJECT base path
$basePath = "/Test_project/public";

// Remove base path
if (stripos($path, $basePath) === 0) {
    $path = substr($path, strlen($basePath));
}

// Remove trailing slash
$path = rtrim($path, "/");

// Default route
if ($path === "") {
    $path = "/";
}

/* ------------------ Run Router ------------------ */
$router->dispatch($path);

<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$customer = $_SESSION["user"] ?? null;

if (!$customer || ($_SESSION["role"] ?? null) !== "customer") {
    header("Location: /Test_project/public/login");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Customer Dashboard</title>

    <link 
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
        rel="stylesheet">

    <style>
        body {
            background: #f4f6f9;
        }

        .sidebar {
            height: 100vh;
            background: #0d1b2a;
            color: white;
            padding: 20px;
        }

        .sidebar a {
            color: #cfd9e6;
            display: block;
            padding: 10px 0;
            font-weight: 500;
            text-decoration: none;
            transition: 0.3s;
        }

        .sidebar a:hover {
            color: white;
            background: #007bff;
            padding-left: 12px;
            border-radius: 6px;
        }

        .content {
            padding: 30px;
        }

        .card-box {
            padding: 20px;
            border-radius: 10px;
            background: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-left: 6px solid #007bff;
            transition: 0.3s;
        }

        .card-box:hover {
            transform: scale(1.02);
            box-shadow: 0 6px 18px rgba(0,0,0,0.15);
        }
    </style>
</head>

<body>

<div class="row g-0">

    <!-- Sidebar -->
    <div class="col-3 sidebar">
        <h3>Customer Panel</h3>
        <hr style="border-color:#cfd9e6">

        <a href="/Test_project/public/customer/dashboard">🏠 Dashboard</a>

        <!-- تم إصلاح الرابط -->
        <a href="/Test_project/public/offers">🎁 View All Offers</a>

        <a href="/Test_project/public/customer/redeemed-offers">📄 My Redeemed Offers</a>

        <a href="/Test_project/public/customer/profile">⚙ Edit Profile</a>

        <a href="/Test_project/public">🚪 Logout</a>
    </div>

    <!-- Content -->
    <div class="col-9 content">
        <h2>Welcome, <?= htmlspecialchars($customer['name']) ?>!</h2>

        <div class="row mt-4">

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Your Email</h4>
                    <p><?= htmlspecialchars($customer["email"]) ?></p>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Your ID</h4>
                    <p><?= $customer["customer_id"] ?></p>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Subscription</h4>
                    <p>
                        <?php 
                        require_once ROOT_PATH . "/app/models/SubscriptionModel.php";
                        $sub = (new SubscriptionModel())->getSubscriptionByCustomerId($customer["customer_id"]);
                        
                        echo $sub 
                            ? ucfirst($sub["tier"]) . " (" . ucfirst(str_replace("_", " ", $sub["program_type"])) . ")"
                            : "No Subscription";
                        ?>
                    </p>
                </div>
            </div>

        </div>

    </div>
</div>

</body>
</html>

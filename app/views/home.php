<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$isCustomer = isset($_SESSION['role']) && $_SESSION['role'] === "customer";
$isMerchant = isset($_SESSION['role']) && $_SESSION['role'] === "merchant";
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Loyalty Program - Home</title>

<style>

    /* =======================
       🔵 Background Animation
    ======================== */
    body {
        margin: 0;
        padding: 0;
        font-family: "Segoe UI", Arial, sans-serif;
        background: linear-gradient(135deg, #0d47a1, #1565c0, #1e88e5, #42a5f5);
        background-size: 400% 400%;
        animation: backgroundMove 12s ease infinite;
        color: white;
    }

    @keyframes backgroundMove {
        0%   { background-position: 0% 50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* =======================
       🔵 Hero Section
    ======================== */
    .hero {
        text-align: center;
        padding: 120px 20px 100px;
    }

    .hero h1 {
        font-size: 54px;
        font-weight: 800;
        letter-spacing: 1px;
        margin-bottom: 15px;
        text-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }

    .hero p {
        font-size: 22px;
        max-width: 650px;
        margin: auto;
        color: #e3f2fd;
        line-height: 1.6;
    }

    /* =======================
       🔵 Buttons Section
    ======================== */
    .buttons {
        margin-top: 35px;
    }

    .btn {
        display: inline-block;
        padding: 14px 32px;
        margin: 10px;
        font-size: 20px;
        font-weight: 600;
        text-decoration: none;
        border-radius: 10px;
        background: rgba(255,255,255,0.15);
        color: white;
        backdrop-filter: blur(7px);
        border: 1px solid rgba(255,255,255,0.25);
        box-shadow: 0 8px 20px rgba(0,0,0,0.2);
        transition: 0.3s;
    }

    .btn:hover {
        background: rgba(255,255,255,0.28);
        transform: translateY(-3px);
    }

    /* Special colors */
    .btn-login        { border-left: 4px solid #00e5ff; }
    .btn-register     { border-left: 4px solid #69f0ae; }
    .btn-subscribe    { border-left: 4px solid #ffd740; }
    .btn-viewoffers   { border-left: 4px solid #ff5252; }

    /* =======================
       🔵 Footer
    ======================== */
    footer {
        margin-top: 120px;
        padding: 20px;
        text-align: center;
        background: rgba(0,0,0,0.25);
        backdrop-filter: blur(7px);
        color: #e3f2fd;
        font-size: 16px;
        letter-spacing: 0.5px;
    }

</style>
</head>

<body>

<!-- Hero Section -->
<div class="hero">
    <h1>Loyalty Program</h1>
    <p>Your gateway to earning points, redeeming exclusive rewards, and enjoying premium merchant offers.</p>

    <div class="buttons">
        <a class="btn btn-login" href="/Test_project/public/login">Login</a>
        <a class="btn btn-register" href="/Test_project/public/select-user-type">Register</a>
        <a class="btn btn-subscribe" href="/Test_project/public/subscription/join">Subscriptions</a>
        <a class="btn btn-viewoffers" href="/Test_project/public/offers">View Offers</a>
    </div>
</div>

<footer>
    Loyalty Program  — maked  by Abdelazeem & Osama  
</footer>

</body>
</html>

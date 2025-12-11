<?php
if (!isset($_SESSION)) session_start();

if (!isset($_SESSION['user']) || ($_SESSION['role'] ?? null) !== 'merchant') {
    header("Location: /Test_project/public/login");
    exit;
}

$merchant = $_SESSION['user'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Edit Profile</title>

<style>

    /* ===== زر Merchant Panel أعلى الشمال ===== */
    .back-top-btn {
        position: absolute;
        top: 20px;
        left: 20px;
        background: #007bff;
        color: white;
        padding: 10px 18px;
        border-radius: 8px;
        text-decoration: none;
        font-size: 16px;
        font-weight: 600;
        transition: 0.3s;
        z-index: 999;
    }
    .back-top-btn:hover {
        background: #0056b3;
    }

    /* ===== خلفية محترفة مثل صفحة اللوجين ===== */
    body {
        margin: 0;
        padding: 0;
        height: 100vh;
        font-family: "Segoe UI", Arial, sans-serif;

        background: linear-gradient(135deg, #0d47a1, #1976d2, #42a5f5);
        background-size: 300% 300%;
        animation: bgMove 10s infinite alternate ease-in-out;

        display: flex;
        justify-content: center;
        align-items: center;
    }

    @keyframes bgMove {
        from { background-position: left; }
        to   { background-position: right; }
    }

    /* ===== الكارت الزجاجي ===== */
    .profile-box {
        width: 90%;
        max-width: 400px;
        padding: 35px;
        border-radius: 16px;

        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(10px);

        box-shadow: 0 15px 35px rgba(0,0,0,0.25);
        animation: fadeIn 0.7s ease;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(30px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    h2 {
        text-align: center;
        color: white;
        font-size: 30px;
        margin-bottom: 20px;
        letter-spacing: 1px;
    }

    label {
        color: #e3e9ff;
        font-weight: 600;
        font-size: 15px;
        margin-top: 15px;
        display: block;
    }

    input {
        width: 100%;
        padding: 13px;
        margin-top: 6px;
        border-radius: 10px;
        font-size: 16px;

        background: rgba(255,255,255,0.9);
        border: 1px solid #b8c6e0;

        transition: 0.25s;
        box-sizing: border-box;
    }

    input:focus {
        border-color: #64b5f6;
        background: #eef6ff;
        outline: none;
        box-shadow: 0 0 10px rgba(100,181,246,0.7);
    }

    button {
        width: 100%;
        padding: 14px;
        font-size: 18px;
        margin-top: 25px;

        background: #2196f3;
        color: white;
        border: none;
        border-radius: 10px;
        cursor: pointer;

        font-weight: 600;
        transition: 0.25s;
        box-sizing: border-box;
    }

    button:hover {
        background: #0d8af0;
        transform: translateY(-2px);
    }

</style>

</head>
<body>

<!-- 🔵 زر Merchant Panel -->
<a class="back-top-btn" href="/Test_project/public/merchant/dashboard">← Merchant Panel</a>

<div class="profile-box">

    <h2>Edit Profile</h2>

    <form action="/Test_project/public/merchant/profile" method="POST">

        <label>Name</label>
        <input type="text" name="name"
               value="<?= htmlspecialchars($merchant['name']) ?>" required>

        <label>Email</label>
        <input type="email" name="email"
               value="<?= htmlspecialchars($merchant['email']) ?>" required>

        <label>Password (leave empty to keep old)</label>
        <input type="password" name="password" placeholder="New password (optional)">

        <button type="submit">Save Changes</button>
    </form>

</div>

</body>
</html>

<?php if (!isset($offer) || !$offer): ?>
    <p style="text-align:center; color:red; font-size:20px;">
        Offer not found.
    </p>
<?php else: ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Offer Receipt</title>

<style>

/* ================================
   GLOBAL BACKGROUND
================================ */
body { 
    font-family: "Segoe UI", Arial, sans-serif;
    margin: 0;
    padding: 40px 20px;
    text-align: center;

    background: linear-gradient(135deg, #0d47a1, #1565c0, #1e88e5);
    background-size: 400% 400%;
    animation: flowBG 14s ease infinite;

    min-height: 100vh;
}

@keyframes flowBG {
    0%   { background-position: 0% 50%; }
    50%  { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

/* ================================
   BACK BUTTON
================================ */
.back-btn {
    display: inline-block;
    background: rgba(255,255,255,0.20);
    color: white;
    padding: 10px 16px;
    border-radius: 8px;
    text-decoration: none;
    font-size: 15px;
    font-weight: 600;

    position: absolute;
    top: 20px;
    left: 20px;

    backdrop-filter: blur(4px);
    box-shadow: 0 4px 14px rgba(0,0,0,0.25);
    transition: 0.25s;
}

.back-btn:hover {
    background: rgba(255,255,255,0.35);
    transform: translateY(-3px);
}

/* ================================
   RECEIPT CARD
================================ */
.receipt {
    width: 90%;
    max-width: 420px;
    margin: 80px auto;

    background: rgba(255,255,255,0.92);
    padding: 28px;
    border-radius: 18px;

    backdrop-filter: blur(8px);
    box-shadow:
        0 12px 28px rgba(0,0,0,0.25),
        0 5px 10px rgba(0,0,0,0.15);

    animation: fadeUp 0.7s ease;
}

@keyframes fadeUp {
    from { opacity: 0; transform: translateY(40px); }
    to   { opacity: 1; transform: translateY(0); }
}

h2 {
    color: #0d47a1;
    margin-bottom: 15px;
    font-size: 26px;
    font-weight: 700;
}

/* ================================
   CONFIRM BUTTON
================================ */
.btn-confirm {
    width: 100%;
    padding: 12px 20px;

    background: linear-gradient(90deg, #28a745, #43c067);
    color: white;

    font-size: 17px;
    font-weight: 700;

    border: none;
    border-radius: 10px;
    cursor: pointer;

    margin-top: 20px;
    transition: 0.25s;

    box-shadow: 0 8px 20px rgba(40,167,69,0.35);
}

.btn-confirm:hover {
    background: linear-gradient(90deg, #43c067, #51d67a);
    transform: translateY(-3px);
    box-shadow: 0 12px 25px rgba(40,167,69,0.45);
}

</style>

</head>
<body>

<!-- Back button -->
<a class="back-btn" href="/Test_project/public/customer/dashboard">← Back</a>

<div class="receipt">
    <h2>Offer Details</h2>

    <p><strong>Offer:</strong> <?= htmlspecialchars($offer['title']) ?></p>
    <p><?= nl2br(htmlspecialchars($offer['description'])) ?></p>
    <p><strong>Discount:</strong> <?= htmlspecialchars($offer['final_discount']) ?>%</p>

    <hr>
    <p>📍 Please visit the nearest branch to apply the discount.</p>

    <!-- Confirm form -->
    <form action="/Test_project/public/customer/confirm-redeem" method="POST">
        <input type="hidden" name="offer_id" value="<?= $offer['offer_id'] ?>">
        <button type="submit" class="btn-confirm">Confirm Offer</button>
    </form>
</div>

</body>
</html>
<?php endif; ?>

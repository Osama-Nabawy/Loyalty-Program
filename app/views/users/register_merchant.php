<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Merchant Registration</title>

<style>

/* -----------------------------------
   GLOBAL GRADIENT BACKGROUND
------------------------------------ */
body {
    font-family: "Segoe UI", Arial, sans-serif;
    margin: 0;
    padding: 0;

    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;

    background: linear-gradient(135deg, #0d47a1, #1565c0, #1e88e5);
    background-size: 400% 400%;
    animation: gradientShift 12s ease infinite;
    position: relative; /* مهم لزر الباك */
}

@keyframes gradientShift {
    0%   { background-position: 0% 50%; }
    50%  { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

/* -----------------------------------
   BACK BUTTON (Top Left)
------------------------------------ */
.back-btn {
    position: absolute;
    top: 20px;
    left: 20px;

    background: rgba(255,255,255,0.25);
    color: #fff;
    padding: 10px 18px;
    border-radius: 10px;
    text-decoration: none;
    font-size: 16px;
    font-weight: 600;

    backdrop-filter: blur(6px);
    box-shadow: 0 4px 14px rgba(0,0,0,0.25);

    transition: 0.25s;
}

.back-btn:hover {
    background: rgba(255,255,255,0.35);
    transform: translateY(-3px);
}

/* -----------------------------------
   PAGE TITLES
------------------------------------ */
h2 {
    text-align: center;
    font-size: 32px;
    color: white;
    margin-bottom: 12px;
    text-shadow: 0 3px 10px rgba(0,0,0,0.25);
    font-weight: 700;
}

.subtitle {
    color: #e3e3e3;
    margin-top: -10px;
    margin-bottom: 18px;
    font-size: 15px;
    text-align: center;
}

/* -----------------------------------
   FORM CARD
------------------------------------ */
form {
    width: 380px;
    padding: 28px;
    border-radius: 18px;

    background: rgba(255,255,255,0.90);
    backdrop-filter: blur(10px);

    box-shadow:
        0 12px 28px rgba(0,0,0,0.25),
        0 5px 10px rgba(0,0,0,0.15);

    animation: fadeUp 0.7s ease;
}

@keyframes fadeUp {
    from { opacity: 0; transform: translateY(40px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* -----------------------------------
   INPUTS
------------------------------------ */
input {
    width: 100%;
    padding: 13px;
    margin: 12px 0;
    font-size: 16px;

    border-radius: 10px;
    border: 1px solid #cfd6e1;
    background: #f9fbff;

    transition: 0.25s ease;
}

input:focus {
    border-color: #1e88e5;
    background: #eef4ff;
    box-shadow: 0 0 10px rgba(30,136,229,0.4);
    outline: none;
    transform: scale(1.02);
}

/* -----------------------------------
   BUTTON
------------------------------------ */
button {
    width: 100%;
    padding: 14px;
    margin-top: 12px;
    font-size: 18px;
    font-weight: 700;

    background: linear-gradient(90deg, #1565c0, #1e88e5);
    color: white;
    border: none;
    border-radius: 12px;
    cursor: pointer;

    box-shadow: 0 8px 20px rgba(21,101,192,0.35);
    transition: 0.25s ease;
}

button:hover {
    background: linear-gradient(90deg, #1e88e5, #42a5f5);
    transform: translateY(-3px);
    box-shadow: 0 12px 25px rgba(21,101,192,0.45);
}

/* -----------------------------------
   FIX WIDTH ALIGNMENT
------------------------------------ */
input, textarea, select, button {
    width: 100%;
    box-sizing: border-box;
}

</style>

</head>
<body>

<!-- 🔵 BACK BUTTON -->
<a href="/Test_project/public/select-user-type" class="back-btn">← Back</a>

<h2>Merchant Registration</h2>
<p class="subtitle">Create your merchant account to start offering deals</p>

<form action="/Test_project/public/register-merchant" method="POST">
    <input type="text" name="name" placeholder="Merchant Name" required>
    <input type="email" name="email" placeholder="Business Email" required>
    <input type="password" name="password" placeholder="Password" required>

    <button type="submit">Register Merchant</button>
</form>

<script>
    const inputs = document.querySelectorAll("input");

    inputs.forEach(input => {
        input.addEventListener("focus", () => input.classList.add("focused"));
        input.addEventListener("blur", () => input.classList.remove("focused"));
    });
</script>

</body>
</html>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Value Based Program</title>

    <style>
        /* ======================================
           GLOBAL BACKGROUND — Same Login Style
        ======================================= */
        body {
            margin: 0;
            padding: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;

            background: linear-gradient(135deg, #0d1b2a, #1b263b);
            position: relative;
        }

        /* Transparent overlay */
        body::before {
            content: "";
            position: absolute;
            inset: 0;
            background: rgba(255,255,255,0.04);
            backdrop-filter: blur(3px);
        }

        /* ======================================
           MAIN CARD (Glassmorphism)
        ======================================= */
        .container {
            position: relative;
            z-index: 2;
            width: 90%;
            max-width: 600px;
            padding: 35px 25px;
            background: rgba(255,255,255,0.15);
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 28px rgba(0,0,0,0.25);
            backdrop-filter: blur(8px);
            animation: fadeIn 0.7s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(25px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        /* ======================================
           TEXT STYLING
        ======================================= */
        h1 {
            font-size: 32px;
            color: #4ee44e; /* لون أخضر مميز يشير للـ charity */
            margin-bottom: 15px;
            text-shadow: 0 2px 6px rgba(0,0,0,0.4);
        }

        p {
            font-size: 18px;
            color: #d9e2ec;
            margin-bottom: 25px;
            line-height: 1.6;
        }

        /* ======================================
           BUTTON
        ======================================= */
        .btn {
            display: inline-block;
            padding: 14px 22px;
            background: #007bff;
            color: white;
            font-size: 18px;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            transition: 0.3s;
        }

        .btn:hover {
            background: #0056d6;
            transform: translateY(-2px);
            box-shadow: 0 6px 18px rgba(0,123,255,0.4);
        }

    </style>
</head>

<body>

<div class="container">
    <h1>Value Based Program</h1>

    <p>
        A percentage of your purchase goes to charity organizations.  
        Thank you for contributing to helping others 💙.
    </p>

    <a class="btn" href="/Test_project/public/">Return Home</a>
</div>

</body>
</html>

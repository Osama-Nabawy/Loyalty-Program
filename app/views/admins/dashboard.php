<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>

    <link 
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
        rel="stylesheet">

    <style>
        body {
            background: #f4f6f9; /* موحّد مع باقي الصفحات */
        }

        /* Sidebar */
        .sidebar {
            height: 100vh;
            background: #0d1b2a; /* أزرق غامق أنيق */
            color: white;
            padding: 20px;
        }

        .sidebar a {
            color: #cfd9e6; /* أزرق فاتح */
            display: block;
            padding: 10px 0;
            text-decoration: none;
            font-weight: 500;
            transition: 0.3s;
        }

        .sidebar a:hover {
            color: #ffffff;
            background: #007bff; /* نفس الزر المستخدم في بقية الصفحات */
            padding-left: 12px;
            border-radius: 6px;
        }

        /* Content area */
        .content {
            padding: 30px;
        }

        h2 {
            color: #333;
        }

        /* Dashboard cards */
        .card-box {
            padding: 20px;
            border-radius: 10px;
            background: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            margin-bottom: 20px;
            border-left: 6px solid #007bff; /* توحيد التصميم */
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

    <div class="col-3 sidebar">
        <h3>Admin Panel</h3>
        <hr style="border-color:#cfd9e6">

        <a href="/Test_project/public/admins/dashboard">🏠 Dashboard</a>
        <a href="/Test_project/public/admins/view_customers">👥 View Customers</a>
        <a href="/Test_project/public/admins/view_merchants">🛒 View Merchants</a>
        <a href="/Test_project/public/admins/view_subscriptions">📄 View Subscriptions</a>
        <a href="/Test_project/public">🚪 Logout</a>
    </div>

    <div class="col-9 content">
        <h2>Welcome, Admin!</h2>

        <div class="row mt-4">

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Total Customers</h4>
                    <p><?= $customerCount ?? 0 ?></p>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Total Merchants</h4>
                    <p><?= $merchantCount ?? 0 ?></p>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card-box">
                    <h4>Active Subscriptions</h4>
                    <p><?= $subscriptionCount ?? 0 ?></p>
                </div>
            </div>

        </div>

    </div>
</div>

</body>
</html>

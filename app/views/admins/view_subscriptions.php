<?php
// $subscriptions يأتي من AdminController
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>View Subscriptions</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>

<body class="bg-light">

    <div class="container mt-4">
        <h2 class="mb-4">All Subscriptions</h2>

        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?= $_SESSION['success'] ?></div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?= $_SESSION['error'] ?></div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>

        <?php if (empty($subscriptions)): ?>
            <div class="alert alert-warning">No subscriptions found.</div>
        <?php else: ?>
            <table class="table table-bordered table-striped">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Customer ID</th>
                        <th>Tier</th>
                        <th>Program Type</th>
                        <th style="width: 150px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($subscriptions as $s): ?>
                        <tr>
                            <td><?= $s['subscription_id'] ?></td>
                            <td><?= $s['customer_id'] ?></td>
                            <td><?= ucfirst($s['tier']) ?></td>
                            <td><?= ucfirst(str_replace("_", " ", $s['program_type'])) ?></td>
                            <td>
                                <a href="/Test_project/public/admins/deleteSubscription?id=<?= $s['subscription_id'] ?>"
                                    class="btn btn-danger btn-sm"
                                    onclick="return confirm('Are you sure you want to delete this subscription?');">
                                    Delete
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <a href="/Test_project/public/admins/dashboard" class="btn btn-secondary mt-3">← Back</a>
    </div>

</body>

</html>
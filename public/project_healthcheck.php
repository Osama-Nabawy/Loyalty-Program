<?php
declare(strict_types=1);

// أظهر الأخطاء أثناء التيست
ini_set('display_errors', '1');
error_reporting(E_ALL);

// تعريف ROOT_PATH عشان نستخدم نفس ال Structure بتاع المشروع
define('ROOT_PATH', dirname(__DIR__));

// جلب كلاس الداتا بيز
require ROOT_PATH . '/app/config/database.php';

// Array هنجمع فيها نتايج كل تيست
$results = [];

function make_result(bool $ok, string $message): array
{
    return ['ok' => $ok, 'message' => $message];
}

// =====================
// 1) اختبار نسخة PHP
// =====================
$results['php_version'] = make_result(
    version_compare(PHP_VERSION, '8.0.0', '>='),
    'Current PHP version: ' . PHP_VERSION
);

// =====================
// 2) اختبار الـ Session
// =====================
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
$_SESSION['__health_test'] = 'ok';
$results['session'] = make_result(
    isset($_SESSION['__health_test']) && $_SESSION['__health_test'] === 'ok',
    'Session is working and writable.'
);

// =====================
// 3) اتصال الداتا بيز
// =====================
$pdo = null;

try {
    $db  = new Database();
    $pdo = $db->connect();
    $results['db_connection'] = make_result(true, 'Connected to database successfully.');
} catch (Throwable $e) {
    $results['db_connection'] = make_result(false, 'Connection error: ' . $e->getMessage());
}

// =====================
// 4) فحص الجداول والـ Columns
// =====================
$tables = [
    'customers' => ['customer_id', 'name', 'email', 'password_hash'],
    'merchants' => ['merchant_id', 'name', 'email', 'password_hash'],
    'admins' => ['admin_id', 'name', 'email', 'password_hash'],
    'subscriptions' => ['subscription_id', 'customer_id', 'merchant_id', 'tier', 'program_type', 'status'],
    'offers' => ['offer_id', 'merchant_id', 'title', 'description', 'discount_value', 'created_at'],
];

if ($pdo !== null) {
    foreach ($tables as $table => $columns) {
        try {
            $stmt = $pdo->query("DESCRIBE `$table`");
            $existingColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);

            $missing = array_diff($columns, $existingColumns);

            if (empty($missing)) {
                $results["table_$table"] = make_result(true, "Table `$table` exists with all required columns.");
            } else {
                $results["table_$table"] = make_result(
                    false,
                    "Table `$table` is missing columns: " . implode(', ', $missing)
                );
            }

        } catch (Throwable $e) {
            $results["table_$table"] = make_result(
                false,
                "Error checking table `$table`: " . $e->getMessage()
            );
        }
    }
}

// =====================
// 5) عرض النتايج HTML
// =====================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Project Health Check</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; max-width: 900px; }
        th, td { border: 1px solid #ccc; padding: 8px 10px; text-align: left; }
        th { background: #f3f3f3; }
        .ok { color: #0a0; font-weight: bold; }
        .fail { color: #c00; font-weight: bold; }
    </style>
</head>
<body>

<h1>Project Health Check</h1>

<table>
    <tr>
        <th>Check</th>
        <th>Status</th>
        <th>Details</th>
    </tr>

    <?php foreach ($results as $name => $result): ?>
        <tr>
            <td><?= htmlspecialchars($name) ?></td>
            <td class="<?= $result['ok'] ? 'ok' : 'fail' ?>">
                <?= $result['ok'] ? 'OK' : 'FAIL' ?>
            </td>
            <td><?= htmlspecialchars($result['message']) ?></td>
        </tr>
    <?php endforeach; ?>
</table>

<p style="margin-top:20px;">
    <a href="/Test_project/public/">← Back to Home</a>
</p>

</body>
</html>

<!-- http://localhost/Test_project/public/project_healthcheck.php -->
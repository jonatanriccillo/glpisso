<?php
/**
 * Vista admin del diagnóstico (equivalente a `plugins:sso:doctor`).
 * Con ?bundle=1 descarga el support bundle JSON redactado.
 */

use GlpiPlugin\Sso\Doctor;

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

if (isset($_GET['bundle'])) {
    $bundle = Doctor::bundle();
    header('Content-Type: application/json; charset=UTF-8');
    header('Content-Disposition: attachment; filename="sso-support-bundle-' . date('Ymd-His') . '.json"');
    echo json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

Html::header(
    __('SSO — Diagnóstico', 'sso'),
    $_SERVER['PHP_SELF'],
    'config',
    'GlpiPlugin\Sso\Menu'
);

$badges = [
    Doctor::OK   => "<span class='badge bg-green-lt'>OK</span>",
    Doctor::WARN => "<span class='badge bg-yellow-lt'>WARN</span>",
    Doctor::FAIL => "<span class='badge bg-red-lt'>FAIL</span>",
];

echo "<div class='card' style='max-width: 1000px; margin: 0 auto;'>";
echo "<div class='card-header d-flex justify-content-between align-items-center'>";
echo "<h3 class='mb-0'>" . __('SSO — Diagnóstico', 'sso') . "</h3>";
echo "<a class='btn btn-sm btn-outline-secondary' href='?bundle=1'>"
    . "<i class='ti ti-download me-1'></i>" . __('Support bundle (JSON redactado)', 'sso') . "</a>";
echo "</div>";
echo "<table class='table table-striped mb-0'>";
echo "<thead><tr><th style='width:70px'></th><th>" . __('Chequeo', 'sso') . "</th><th>" . __('Detalle', 'sso') . "</th></tr></thead><tbody>";

$section = '';
foreach (Doctor::run() as $check) {
    if ($check['section'] !== $section) {
        $section = $check['section'];
        echo "<tr><td colspan='3' class='fw-bold text-uppercase text-secondary'>" . htmlspecialchars($section) . "</td></tr>";
    }
    echo '<tr>';
    echo '<td>' . $badges[$check['status']] . '</td>';
    echo '<td>' . htmlspecialchars($check['name']) . '</td>';
    echo '<td>' . htmlspecialchars($check['detail']) . '</td>';
    echo '</tr>';
}

echo '</tbody></table></div>';

Html::footer();

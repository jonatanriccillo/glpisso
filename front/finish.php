<?php
/**
 * Finalización del login: consume el ticket one-shot emitido por acs.php /
 * callback.php y crea la sesión GLPI. GET top-level (la cookie viaja) +
 * STRATEGY_NO_CHECK.
 */

use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\LoginPipeline;

include('../../../inc/includes.php');

// Sólo GET/HEAD: el ticket one-shot se canjea por navegación top-level.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

try {
    LoginPipeline::completeFromTicket((string) ($_GET['t'] ?? ''));
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_validation', Log::LEVEL_ERROR, 'finish failed: ' . $e->getMessage());
    LoginPipeline::failPage(__('Authentication failed', 'sso'));
}

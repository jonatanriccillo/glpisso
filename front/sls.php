<?php
/**
 * SAML Single Logout Service (redirect binding, GET top-level). Procesa la
 * LogoutResponse de nuestro SLO o un LogoutRequest IdP-initiated. Público
 * (STRATEGY_NO_CHECK) pero CON sesión: el caso IdP-initiated la destruye.
 */

use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

// Sólo GET/HEAD: el SLS usa el binding HTTP-Redirect.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

global $CFG_GLPI;

$fallback = rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/') . '/index.php?noAUTO=1';

try {
    $url = SamlClient::handleSls();
    Html::redirect($url ?? $fallback);
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_validation', Log::LEVEL_ERROR, 'SLS rejected: ' . $e->getMessage());
    Html::redirect($fallback);
}

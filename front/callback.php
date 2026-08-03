<?php
/**
 * OIDC redirect_uri (GET top-level del IdP). Público (STRATEGY_NO_CHECK).
 * Igual que el ACS SAML: acá NO se crea la sesión — se valida el retorno,
 * se emite el ticket one-shot y se redirige a finish.php.
 */

use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\LoginPipeline;
use GlpiPlugin\Sso\OidcClient;

include('../../../inc/includes.php');

// Sólo GET/HEAD: el redirect_uri OIDC llega por navegación top-level.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

try {
    [$idp, $identity, $redirect, $session] = OidcClient::handleCallback();
    $url = LoginPipeline::issueTicket($idp, $identity, $redirect, $session);
    Html::redirect($url);
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_validation', Log::LEVEL_ERROR, 'callback rejected: ' . $e->getMessage());
    LoginPipeline::failPage(__('Authentication failed', 'sso'));
}

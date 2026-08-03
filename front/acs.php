<?php
/**
 * SAML Assertion Consumer Service (POST del IdP, cross-site).
 * Stateless + STRATEGY_NO_CHECK: acá NO se crea la sesión — se valida la
 * Response, se emite un ticket one-shot y se redirige a finish.php (GET),
 * que sí corre con sesión. Ver PLAN.md (spike M0 #2).
 */

use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\LoginPipeline;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

// Sólo POST: el binding HTTP-POST del ACS no admite otro método.
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}

try {
    [$idp, $identity, $redirect, $session] = SamlClient::handleAcs();
    $url = LoginPipeline::issueTicket($idp, $identity, $redirect, $session);
    Html::redirect($url);
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_validation', Log::LEVEL_ERROR, 'ACS rejected: ' . $e->getMessage());
    LoginPipeline::failPage(__('Authentication failed', 'sso'));
}

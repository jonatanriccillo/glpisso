<?php
/**
 * Inicio del flujo SSO: /plugins/sso/front/login.php?idp=N
 * Público (STRATEGY_NO_CHECK). Redirige al IdP.
 */

use GlpiPlugin\Sso\Idp;
use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\LoginPipeline;
use GlpiPlugin\Sso\OidcClient;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

// Sólo GET/HEAD: el inicio de flujo es una navegación, no un POST.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

$idps_id = (int) ($_GET['idp'] ?? 0);
$redirect = (string) ($_GET['redirect'] ?? '');

$idp = new Idp();
if (
    !$idps_id
    || !$idp->getFromDB($idps_id)
    || !(bool) $idp->fields['is_active']
    || (bool) $idp->fields['is_deleted']
) {
    Log::record('login_denied', Log::LEVEL_WARNING, 'login start with unknown/inactive idp: ' . $idps_id);
    LoginPipeline::failPage(__('Unknown or inactive identity provider', 'sso'));
}

try {
    switch ($idp->fields['protocol']) {
        case Idp::PROTO_SAML:
            (new SamlClient($idp))->startLogin($redirect); // redirige vía RedirectException
            break;
        case Idp::PROTO_OIDC:
            (new OidcClient($idp))->startLogin($redirect); // ídem
            break;
        default:
            LoginPipeline::failPage(__('This provider protocol is not available yet', 'sso'));
    }
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_config', Log::LEVEL_ERROR, 'login start failed: ' . $e->getMessage(), ['idps_id' => $idps_id]);
    LoginPipeline::failPage(__('Authentication failed', 'sso'));
}

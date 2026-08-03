<?php
/**
 * Single Logout: cierra la sesión GLPI (si sigue viva) y redirige al IdP
 * de la sesión (end_session OIDC / SLO SAML) usando el hint one-shot cuyo
 * token viaja en la cookie `sso_lt`. Público (STRATEGY_NO_CHECK).
 */

use GlpiPlugin\Sso\Config;
use GlpiPlugin\Sso\Idp;
use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\OidcClient;
use GlpiPlugin\Sso\RequestState;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

// Sólo GET/HEAD: el logout se dispara por navegación top-level.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

global $CFG_GLPI;

$fallback = rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/') . '/index.php?noAUTO=1';

// La cookie se limpia SIEMPRE (el hint en DB es one-shot igual).
$token = (string) ($_COOKIE['sso_lt'] ?? '');
setcookie('sso_lt', '', ['expires' => time() - 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);

// Si vinieron directo acá con la sesión viva, cerrarla primero.
if (Session::getLoginUserID()) {
    Session::cleanOnLogout();
}

try {
    if ($token === '' || (int) Config::value('idp_logout') !== 1) {
        Html::redirect($fallback);
    }

    $hint = RequestState::consume(RequestState::KIND_LOGOUT_HINT, $token);
    if ($hint === null) {
        Html::redirect($fallback);
    }

    $idp = new Idp();
    if (!$idp->getFromDB((int) $hint['idps_id']) || !(bool) $idp->fields['is_active']) {
        Html::redirect($fallback);
    }

    if ($idp->fields['protocol'] === Idp::PROTO_SAML) {
        (new SamlClient($idp))->startSlo($hint); // redirige, no retorna
    }

    $url = (new OidcClient($idp))->logoutUrl($hint);
    Log::record('logout', Log::LEVEL_INFO, 'OIDC RP-initiated logout', ['idps_id' => (int) $idp->getID()]);
    Html::redirect($url ?? $fallback);
} catch (\Glpi\Exception\RedirectException $e) {
    throw $e; // Html::redirect: la maneja el kernel, no es un error
} catch (\Throwable $e) {
    Log::record('error_config', Log::LEVEL_ERROR, 'logout failed: ' . $e->getMessage());
    Html::redirect($fallback);
}

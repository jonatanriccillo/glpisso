<?php
/**
 * Auditoría de eventos de autenticación SSO.
 */

use GlpiPlugin\Sso\Log;

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

Html::header(
    Log::getTypeName(),
    $_SERVER['PHP_SELF'],
    'config',
    'GlpiPlugin\Sso\Menu'
);

Search::show(Log::class);

Html::footer();

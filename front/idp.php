<?php
/**
 * Lista de proveedores de identidad configurados.
 */

use GlpiPlugin\Sso\Idp;

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

Html::header(
    Idp::getTypeName(2),
    $_SERVER['PHP_SELF'],
    'config',
    'GlpiPlugin\Sso\Menu'
);

if (Idp::canCreate()) {
    echo "<div class='mb-3'><a class='btn btn-primary' href='"
        . htmlspecialchars(Idp::getFormURL(), ENT_QUOTES, 'UTF-8')
        . "'><i class='ti ti-plus'></i> " . __('Add an identity provider', 'sso') . "</a></div>";
}

Search::show(Idp::class);

Html::footer();

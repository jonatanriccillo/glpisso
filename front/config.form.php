<?php
/**
 * Config global del plugin (glpi_configs, contexto plugin:sso).
 */

use GlpiPlugin\Sso\Config;

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

if (isset($_POST['update_config'])) {
    Session::checkRight('plugin_sso', UPDATE);
    Config::set($_POST);
    Session::addMessageAfterRedirect(__('Configuration saved', 'sso'), false, INFO);
    Html::back();
}

Html::header(
    __('SSO — General configuration', 'sso'),
    $_SERVER['PHP_SELF'],
    'config',
    'GlpiPlugin\Sso\Menu'
);

Config::showForm();

Html::footer();

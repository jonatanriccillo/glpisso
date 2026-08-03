<?php
/**
 * Lista de reglas de autorización SSO (UI genérica del core).
 */

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

$rulecollection = new \GlpiPlugin\Sso\RuleAuthCollection();

include(GLPI_ROOT . '/front/rule.common.php');

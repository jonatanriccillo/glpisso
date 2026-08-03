<?php

namespace GlpiPlugin\Sso;

use RuleCollection;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Collection de las reglas de autorización SSO. Acumulativa (no corta en el
 * primer match, igual que RuleRight): varias reglas pueden sumar entidades,
 * perfiles y grupos; `_deny_login` corta en la aplicación (LoginPipeline).
 */
class RuleAuthCollection extends RuleCollection
{
    public static $rightname = 'plugin_sso';

    public $stop_on_first_match = false;
    public $can_replay_rules    = false;
    public $menu_option         = 'plugin_sso';

    public function getTitle()
    {
        return __('SSO authorization rules', 'sso');
    }
}

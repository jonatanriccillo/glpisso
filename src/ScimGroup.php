<?php

namespace GlpiPlugin\Sso;

use CommonDBTM;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/** Ownership persistente IdP SCIM ↔ grupo core GLPI. */
class ScimGroup extends CommonDBTM
{
    public static $rightname = 'plugin_sso';

    public static function getTypeName($nb = 0): string
    {
        return _n('SCIM managed group', 'SCIM managed groups', $nb, 'sso');
    }
}

<?php

namespace GlpiPlugin\Sso;

use CommonDBTM;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Identidad estable: (IdP, subject) ↔ usuario GLPI. El subject es el `sub`
 * OIDC o el NameID SAML; sobrevive cambios de email en el IdP.
 */
class UserLink extends CommonDBTM
{
    public static $rightname = 'plugin_sso';

    public static function getTypeName($nb = 0): string
    {
        return _n('SSO identity link', 'SSO identity links', $nb, 'sso');
    }

    /** @return int|null users_id vinculado, o null si no hay link */
    public static function lookup(int $idps_id, string $subject): ?int
    {
        global $DB;

        foreach ($DB->request([
            'SELECT' => ['id', 'users_id'],
            'FROM'   => self::getTable(),
            'WHERE'  => ['idps_id' => $idps_id, 'subject' => $subject],
            'LIMIT'  => 1,
        ]) as $row) {
            $DB->update(self::getTable(), ['last_login' => date('Y-m-d H:i:s')], ['id' => (int) $row['id']]);
            return (int) $row['users_id'];
        }
        return null;
    }

    /** Crea el vínculo (primera vinculación por matching/JIT/SCIM). */
    public static function link(int $idps_id, string $subject, int $users_id, bool $login = true): bool
    {
        global $DB;

        try {
            return (bool) $DB->insert(self::getTable(), [
                'idps_id'       => $idps_id,
                'users_id'      => $users_id,
                'subject'       => $subject,
                'date_creation' => date('Y-m-d H:i:s'),
                'last_login'    => $login ? date('Y-m-d H:i:s') : null,
            ]);
        } catch (\Throwable $e) {
            Log::record('error_state', Log::LEVEL_ERROR, 'link failed: ' . $e->getMessage(), [
                'idps_id'  => $idps_id,
                'users_id' => $users_id,
            ]);
            return false;
        }
    }
}

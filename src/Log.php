<?php

namespace GlpiPlugin\Sso;

use CommonDBTM;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Auditoría de eventos de auth (ok/fail/JIT/regla/logout/error). Nunca guarda
 * tokens ni assertions completas. Purga por retención (cron purgelogs).
 */
class Log extends CommonDBTM
{
    public static $rightname = 'plugin_sso';

    public const LEVEL_INFO    = 'info';
    public const LEVEL_WARNING = 'warning';
    public const LEVEL_ERROR   = 'error';

    public static function getTypeName($nb = 0): string
    {
        return __('SSO authentication log', 'sso');
    }

    public static function getIcon(): string
    {
        return 'ti ti-list-details';
    }

    /**
     * Registra un evento. Jamás rompe el flujo que lo llama: cualquier error
     * de logging se traga (best-effort).
     *
     * $ctx opcional: idps_id, users_id + cualquier detalle extra (va a JSON).
     */
    public static function record(string $event, string $level, string $message, array $ctx = []): void
    {
        global $DB;

        try {
            $idps_id  = (int) ($ctx['idps_id'] ?? 0);
            $users_id = (int) ($ctx['users_id'] ?? 0);
            unset($ctx['idps_id'], $ctx['users_id']);

            $DB->insert(self::getTable(), [
                'date'     => date('Y-m-d H:i:s'),
                'idps_id'  => $idps_id,
                'users_id' => $users_id,
                'event'    => substr($event, 0, 50),
                'level'    => substr($level, 0, 10),
                'ip'       => substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45),
                'message'  => substr($message, 0, 255),
                'details'  => $ctx === [] ? null : json_encode($ctx, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ]);
        } catch (\Throwable $e) {
            // best-effort
        }
    }

    /** Sólo si debug está activo en la config. */
    public static function debug(string $event, string $message, array $ctx = []): void
    {
        if ((int) Config::value('debug') === 1) {
            self::record($event, self::LEVEL_INFO, $message, $ctx);
        }
    }

    /** @return int filas purgadas */
    public static function purgeOlderThan(int $days): int
    {
        global $DB;

        $days = max(7, $days);
        $DB->delete(self::getTable(), [
            'date' => ['<', date('Y-m-d H:i:s', time() - $days * DAY_TIMESTAMP)],
        ]);
        return max(0, (int) $DB->affectedRows());
    }

    public static function canCreate(): bool
    {
        return false; // se escribe sólo por código
    }

    public function rawSearchOptions(): array
    {
        $tab = [];

        $tab[] = ['id' => 'common', 'name' => self::getTypeName()];
        $tab[] = [
            'id' => 1, 'table' => self::getTable(), 'field' => 'date',
            'name' => _n('Date', 'Dates', 1), 'datatype' => 'datetime',
            'massiveaction' => false,
        ];
        $tab[] = [
            'id' => 2, 'table' => self::getTable(), 'field' => 'event',
            'name' => __('Event', 'sso'), 'datatype' => 'string',
        ];
        $tab[] = [
            'id' => 3, 'table' => self::getTable(), 'field' => 'level',
            'name' => __('Level', 'sso'), 'datatype' => 'string',
        ];
        $tab[] = [
            'id' => 4, 'table' => Idp::getTable(), 'field' => 'name',
            'name' => Idp::getTypeName(1), 'datatype' => 'dropdown',
            'linkfield' => 'idps_id',
        ];
        $tab[] = [
            'id' => 5, 'table' => 'glpi_users', 'field' => 'name',
            'name' => \User::getTypeName(1), 'datatype' => 'dropdown',
            'linkfield' => 'users_id', 'right' => 'all',
        ];
        $tab[] = [
            'id' => 6, 'table' => self::getTable(), 'field' => 'message',
            'name' => __('Message', 'sso'), 'datatype' => 'string',
        ];
        $tab[] = [
            'id' => 7, 'table' => self::getTable(), 'field' => 'ip',
            'name' => __('IP address', 'sso'), 'datatype' => 'string',
        ];

        return $tab;
    }
}

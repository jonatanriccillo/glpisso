<?php

namespace GlpiPlugin\Sso;

use CommonGLPI;
use CronTask;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/** Tareas de cron del plugin: purga de estado de flujo y de auditoría. */
class Cron extends CommonGLPI
{
    public static function getTypeName($nb = 0): string
    {
        return __('SSO', 'sso');
    }

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'purgestate' => ['description' => __('Purge expired SSO flow state (tokens, tickets, replay cache)', 'sso')],
            'purgelogs'  => ['description' => __('Purge SSO authentication log beyond retention', 'sso')],
            'certwatch'  => ['description' => __('Warn about SAML certificates nearing expiration', 'sso')],
            default      => ['description' => ''],
        };
    }

    public static function cronPurgestate(CronTask $task): int
    {
        $n = RequestState::purgeExpired();
        $task->addVolume($n);
        return $n > 0 ? 1 : 0;
    }

    public static function cronPurgelogs(CronTask $task): int
    {
        $n = Log::purgeOlderThan((int) Config::value('log_retention_days'));
        $task->addVolume($n);
        return $n > 0 ? 1 : 0;
    }

    public static function cronCertwatch(CronTask $task): int
    {
        $n = CertWatch::checkAndLog();
        $task->addVolume($n);
        return $n > 0 ? 1 : 0;
    }
}

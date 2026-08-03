<?php

namespace GlpiPlugin\Sso;

use CommonGLPI;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

class Menu extends CommonGLPI
{
    public static $rightname = 'plugin_sso';

    public static function getTypeName($nb = 0): string
    {
        return __('SSO', 'sso');
    }

    public static function getMenuName(): string
    {
        return self::getTypeName();
    }

    public static function getIcon(): string
    {
        return 'ti ti-fingerprint';
    }

    /** Página principal del menú: la lista de IdPs. */
    public static function getSearchURL($full = true): string
    {
        $path = '/plugins/sso/front/idp.php';
        return $full ? \Html::getPrefixedUrl($path) : ltrim($path, '/');
    }

    public static function getMenuContent()
    {
        $base = '/plugins/sso';
        return [
            'title' => self::getMenuName(),
            'page'  => $base . '/front/idp.php',
            'icon'  => self::getIcon(),
            'options' => [
                'config' => [
                    'title' => __('General configuration', 'sso'),
                    'page'  => $base . '/front/config.form.php',
                ],
                'log' => [
                    'title' => __('Authentication log', 'sso'),
                    'page'  => $base . '/front/log.php',
                ],
            ],
        ];
    }
}

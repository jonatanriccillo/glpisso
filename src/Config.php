<?php

namespace GlpiPlugin\Sso;

use Config as GlpiConfig;
use Dropdown;
use Html;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Config global del plugin. Sin tabla propia: usa el storage core
 * `glpi_configs` con contexto `plugin:sso`.
 */
class Config
{
    public const CONTEXT = 'plugin:sso';

    public const DEFAULTS = [
        'base_url'           => '',   // vacío = $CFG_GLPI['url_base']
        'forced_sso'         => 0,    // auto-redirect del login al IdP default
        'default_idps_id'    => 0,
        'hrd_enabled'        => 0,    // elegir IdP por dominio del email
        'adopt_existing'     => 1,    // matching adopta usuarios preexistentes
        'fail_closed'        => 0,    // sin regla matcheada => rechazar login
        'idp_logout'         => 1,    // al cerrar sesión GLPI, cerrar la del IdP
        'log_retention_days' => 90,
        'debug'              => 0,
    ];

    /** @return array<string, mixed> defaults + valores guardados */
    public static function get(): array
    {
        return array_merge(self::DEFAULTS, GlpiConfig::getConfigurationValues(self::CONTEXT));
    }

    public static function value(string $key): mixed
    {
        return self::get()[$key] ?? null;
    }

    /** Guarda sólo claves conocidas. */
    public static function set(array $values): void
    {
        GlpiConfig::setConfigurationValues(self::CONTEXT, array_intersect_key($values, self::DEFAULTS));
    }

    /** Base URL efectiva (sin barra final) de la que derivan ACS/callback/metadata. */
    public static function baseUrl(): string
    {
        global $CFG_GLPI;

        $configured = trim((string) self::value('base_url'));
        $url = $configured !== '' ? $configured : (string) ($CFG_GLPI['url_base'] ?? '');
        return rtrim($url, '/');
    }

    public static function showForm(): void
    {
        $values = self::get();
        $action = \Html::getPrefixedUrl('/plugins/sso/front/config.form.php');

        echo "<form method='post' action='" . htmlspecialchars($action, ENT_QUOTES, 'UTF-8') . "'>";
        echo "<div class='card' style='max-width: 900px; margin: 0 auto;'>";
        echo "<div class='card-header'><h3>" . __('SSO — General configuration', 'sso') . "</h3></div>";
        echo "<table class='tab_cadre_fixe'>";

        echo "<tr class='tab_bg_1'><td style='width: 40%'>" . __('Public base URL', 'sso')
            . "<br><span class='text-muted'>" . sprintf(__('Empty = GLPI URL (%s)', 'sso'), self::baseUrl()) . "</span></td><td>";
        echo Html::input('base_url', ['value' => $values['base_url'], 'style' => 'width: 100%']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Forced SSO (auto-redirect to default IdP)', 'sso')
            . "<br><span class='text-muted'>" . __('Bypass: add ?noSSO=1 to the login URL', 'sso') . "</span></td><td>";
        Dropdown::showYesNo('forced_sso', (int) $values['forced_sso']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Default identity provider', 'sso') . "</td><td>";
        Idp::dropdownActive('default_idps_id', (int) $values['default_idps_id']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Home realm discovery (pick IdP by email domain)', 'sso') . "</td><td>";
        Dropdown::showYesNo('hrd_enabled', (int) $values['hrd_enabled']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Adopt pre-existing users on first match', 'sso')
            . "<br><span class='text-muted'>" . __('Links the account and switches authtype to EXTERNAL', 'sso') . "</span></td><td>";
        Dropdown::showYesNo('adopt_existing', (int) $values['adopt_existing']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Fail closed (deny login when no rule matched)', 'sso') . "</td><td>";
        Dropdown::showYesNo('fail_closed', (int) $values['fail_closed']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Log out from the identity provider too (Single Logout)', 'sso') . "</td><td>";
        Dropdown::showYesNo('idp_logout', (int) $values['idp_logout']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Log retention (days)', 'sso') . "</td><td>";
        Dropdown::showNumber('log_retention_days', ['value' => (int) $values['log_retention_days'], 'min' => 7, 'max' => 3650]);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __('Debug logging', 'sso') . "</td><td>";
        Dropdown::showYesNo('debug', (int) $values['debug']);
        echo "</td></tr>";

        echo "<tr class='tab_bg_2'><td colspan='2' class='center'>";
        echo Html::submit(_sx('button', 'Save'), ['name' => 'update_config', 'class' => 'btn btn-primary']);
        echo "</td></tr>";

        echo "</table></div>";
        Html::closeForm();
    }
}

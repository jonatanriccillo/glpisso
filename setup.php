<?php
/**
 * SSO plugin for GLPI 11.
 *
 * Login contra IdPs externos vía SAML 2.0 y OpenID Connect: multi-IdP,
 * aprovisionamiento JIT, motor de reglas nativo para autorización y Single
 * Logout. Ver BLUEPRINT.md para el plan completo.
 *
 * Licensed under GPLv3.
 */

use Glpi\Http\Firewall;
use Glpi\Http\SessionManager;
use GlpiPlugin\Sso\Cron;
use GlpiPlugin\Sso\Idp;
use GlpiPlugin\Sso\Log;
use GlpiPlugin\Sso\Menu;
use GlpiPlugin\Sso\Profile;
use GlpiPlugin\Sso\RuleAuth;
use GlpiPlugin\Sso\RuleAuthCollection;

define('PLUGIN_SSO_VERSION', '1.0.1');
define('PLUGIN_SSO_MIN_GLPI', '11.0.0');
define('PLUGIN_SSO_MAX_GLPI', '11.9.99');

function plugin_init_sso(): void
{
    global $PLUGIN_HOOKS;

    // El hook display_login corre también sin sesión: cargar el dominio del
    // plugin de forma explícita para que sus textos se traduzcan allí.
    Plugin::loadLang('sso');

    $PLUGIN_HOOKS['csrf_compliant']['sso'] = true;
    $PLUGIN_HOOKS['change_profile']['sso'] = [Profile::class, 'initProfile'];

    // Campos cifrados con GLPIKey: registrarlos para que
    // `glpi:security:changekey` los re-cifre al rotar la clave. Sin esto,
    // una rotación deja los secretos indescifrables.
    $PLUGIN_HOOKS['secured_fields']['sso'] = [
        'glpi_plugin_sso_idps.client_secret',
        'glpi_plugin_sso_idps.sp_private_key',
    ];

    // Endpoints públicos del flujo SSO (M1+): accesibles sin login previo.
    // El patrón es relativo a la raíz del plugin (spike M0 #1).
    Firewall::addPluginStrategyForLegacyScripts(
        'sso',
        '#^/front/(login|acs|callback|finish|sls|metadata|logout|scim)\.php#',
        Firewall::STRATEGY_NO_CHECK
    );

    // El ACS recibe POST cross-site del IdP: stateless = sin sesión y sin
    // check CSRF. La sesión se crea recién en finish.php (spike M0 #2).
    // OJO: sls.php NO es stateless — el SLO IdP-initiated (GET top-level)
    // necesita la sesión para poder destruirla.
    SessionManager::registerPluginStatelessPath('sso', '#^/front/acs\.php#');
    SessionManager::registerPluginStatelessPath('sso', '#^/front/scim\.php#');

    // Botones "Iniciar sesión con..." en la página de login.
    $PLUGIN_HOOKS['display_login']['sso'] = 'plugin_sso_display_login';

    // Pestaña de derechos en Administración > Perfiles.
    Plugin::registerClass(Profile::class, ['addtabon' => 'Profile']);

    // Modelos / cron (Search, displaypreferences, itemtype canónico).
    foreach ([Idp::class, Log::class, Cron::class] as $class) {
        Plugin::registerClass($class);
    }

    // Aliases cortos para la maquinaria de GLPI (itemtype de CronTask,
    // sub_type de las reglas en glpi_rules, URLs front/ruleauth*).
    foreach ([
        'PluginSsoCron'               => Cron::class,
        'PluginSsoRuleAuth'           => RuleAuth::class,
        'PluginSsoRuleAuthCollection' => RuleAuthCollection::class,
    ] as $alias => $class) {
        // El alias se define recién acá: el análisis estático no puede verlo.
        // @phpstan-ignore function.impossibleType
        if (!class_exists($alias, false)) {
            class_alias($class, $alias);
        }
    }

    // Reglas de autorización en Administración > Reglas (engine nativo).
    // OJO: se registra el nombre namespaced — static::class ignora los alias,
    // así que el sub_type real en glpi_rules es GlpiPlugin\Sso\RuleAuth.
    Plugin::registerClass(RuleAuthCollection::class, ['rulecollections_types' => true]);

    if (!Session::getLoginUserID()) {
        return;
    }

    if (Session::haveRight('plugin_sso', READ)) {
        $PLUGIN_HOOKS['menu_toadd']['sso'] = ['config' => Menu::class];
        $PLUGIN_HOOKS['config_page']['sso'] = 'front/idp.php';
    }
}

function plugin_version_sso(): array
{
    return [
        'name'         => 'SSO',
        'version'      => PLUGIN_SSO_VERSION,
        'author'       => 'Jonatan Riccillo',
        'license'      => 'GPLv3',
        'homepage'     => '',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SSO_MIN_GLPI,
                'max' => PLUGIN_SSO_MAX_GLPI,
            ],
        ],
    ];
}

function plugin_sso_check_prerequisites(): bool
{
    if (version_compare(GLPI_VERSION, PLUGIN_SSO_MIN_GLPI, 'lt')) {
        echo Plugin::messageIncompatible('core', PLUGIN_SSO_MIN_GLPI);
        return false;
    }

    // Requisitos efectivos del plugin: fallar ANTES de instalar, con mensaje
    // útil, y no con un fatal a mitad de un login SAML/OIDC.
    if (version_compare(PHP_VERSION, '8.2.0', 'lt')) {
        echo 'SSO plugin requires PHP >= 8.2 (found ' . PHP_VERSION . ').';
        return false;
    }
    $missing = array_filter(
        ['openssl', 'curl', 'dom', 'json', 'mbstring'],
        static fn (string $ext): bool => !extension_loaded($ext)
    );
    if ($missing !== []) {
        echo 'SSO plugin requires the following PHP extensions: '
            . implode(', ', $missing) . '.';
        return false;
    }

    return true;
}

function plugin_sso_check_config($verbose = false): bool
{
    return true;
}

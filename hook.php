<?php
/**
 * Install / uninstall hooks para SSO.
 */

use GlpiPlugin\Sso\Config;
use GlpiPlugin\Sso\Profile;

function plugin_sso_tables(): array
{
    return [
        'glpi_plugin_sso_idps',
        'glpi_plugin_sso_requeststates',
        'glpi_plugin_sso_userlinks',
        'glpi_plugin_sso_scimgroups',
        'glpi_plugin_sso_logs',
        'glpi_plugin_sso_profiles',
    ];
}

function plugin_sso_install(): bool
{
    global $DB;

    if (!$DB->tableExists('glpi_plugin_sso_idps')) {
        $DB->runFile(Plugin::getPhpDir('sso') . '/sql/install.sql');
    } else {
        plugin_sso_migrate($DB);
    }

    Profile::initProfile();
    if (isset($_SESSION['glpiactiveprofile']['id'])) {
        Profile::createFirstAccess((int) $_SESSION['glpiactiveprofile']['id']);
    }

    plugin_sso_install_displayprefs();

    // MODE_EXTERNAL, no INTERNAL: con un cron externo configurado (imagen
    // oficial, cron del host) GLPI no ejecuta los internos en page-hits, y
    // los tres quedaban con lastrun NULL para siempre (lo detectó el doctor
    // en el lab: 4 días desplegado, purgestate jamás corrido).
    // Purga de estado de flujo (state/tickets/replay vencidos): corta y frecuente.
    CronTask::register('PluginSsoCron', 'purgestate', 15 * MINUTE_TIMESTAMP, [
        'state' => CronTask::STATE_WAITING,
        'mode'  => CronTask::MODE_EXTERNAL,
    ]);
    // Retención de la auditoría.
    CronTask::register('PluginSsoCron', 'purgelogs', DAY_TIMESTAMP, [
        'state' => CronTask::STATE_WAITING,
        'mode'  => CronTask::MODE_EXTERNAL,
    ]);
    // Vigilancia de certificados SAML por vencer (<30 días).
    CronTask::register('PluginSsoCron', 'certwatch', DAY_TIMESTAMP, [
        'state' => CronTask::STATE_WAITING,
        'mode'  => CronTask::MODE_EXTERNAL,
    ]);

    return true;
}

/**
 * Columnas por defecto en la lista de IdPs. Los `num` matchean los IDs de
 * Idp::rawSearchOptions().
 */
function plugin_sso_install_displayprefs(): void
{
    global $DB;

    $itemtype = \GlpiPlugin\Sso\Idp::getType();
    $prefs = [2 => 1, 3 => 2, 4 => 3]; // protocol, is_active, ranking
    foreach ($prefs as $num => $rank) {
        $exists = countElementsInTable('glpi_displaypreferences',
            ['itemtype' => $itemtype, 'num' => $num, 'users_id' => 0]);
        if ($exists === 0) {
            $DB->insert('glpi_displaypreferences',
                ['itemtype' => $itemtype, 'num' => $num, 'rank' => $rank, 'users_id' => 0]);
        }
    }
}

/**
 * Trae instalaciones existentes al día sin uninstall (Migration::addField).
 */
function plugin_sso_migrate($DB): void
{
    $migration = new Migration(PLUGIN_SSO_VERSION);

    // M2: cache de discovery/JWKS OIDC en la fila del IdP.
    foreach ([
        'discovery_cache'     => 'text',
        'discovery_cached_at' => 'timestamp',
        'jwks_cache'          => 'text',
        'jwks_cached_at'      => 'timestamp',
    ] as $field => $type) {
        if (!$DB->fieldExists('glpi_plugin_sso_idps', $field)) {
            $migration->addField('glpi_plugin_sso_idps', $field, $type);
        }
    }

    // M6: provisioning SCIM por IdP. CREATE TABLE IF NOT EXISTS no agrega
    // columnas a una instalación 0.1.x existente, por eso deben migrarse.
    if (!$DB->fieldExists('glpi_plugin_sso_idps', 'scim_enabled')) {
        $migration->addField(
            'glpi_plugin_sso_idps',
            'scim_enabled',
            'TINYINT NOT NULL DEFAULT 0'
        );
    }
    if (!$DB->fieldExists('glpi_plugin_sso_idps', 'scim_token_hash')) {
        $migration->addField(
            'glpi_plugin_sso_idps',
            'scim_token_hash',
            "VARCHAR(64) NOT NULL DEFAULT ''"
        );
    }

    // 0.2.12: presentación configurable de cada IdP en el login.
    if (!$DB->fieldExists('glpi_plugin_sso_idps', 'login_presentation')) {
        $migration->addField(
            'glpi_plugin_sso_idps',
            'login_presentation',
            "VARCHAR(20) NOT NULL DEFAULT 'button'"
        );
    }

    $migration->executeMigration();

    // 0.3.0: crons a MODE_EXTERNAL en instalaciones existentes (ver arriba).
    $DB->update(
        'glpi_crontasks',
        ['mode' => CronTask::MODE_EXTERNAL],
        ['itemtype' => 'PluginSsoCron', 'mode' => CronTask::MODE_INTERNAL]
    );

    // 0.3.0: los secretos vacíos deben ser NULL, no '': el re-cifrado de
    // `glpi:security:changekey` (hook secured_fields) recorre lo no-NULL y
    // convertiría un '' en ciphertext, rompiendo la lógica de "sin secreto".
    foreach (['client_secret', 'sp_private_key'] as $secret_col) {
        $DB->update(
            'glpi_plugin_sso_idps',
            [$secret_col => null],
            [$secret_col => '']
        );
    }

    // 0.2.1: GLPI 11 no incluye ti-brand-openid en su build de Tabler.
    // Sustituir el valor sugerido anteriormente por un ícono disponible.
    $DB->update(
        'glpi_plugin_sso_idps',
        ['icon' => 'ti ti-circle-key'],
        ['icon' => 'ti ti-brand-openid']
    );

    // 0.2.4: los pictogramas monocromos de Tabler no son logos oficiales.
    foreach ([
        'ti ti-brand-google'  => 'sso-brand-google',
        'ti ti-brand-windows' => 'sso-brand-microsoft',
    ] as $old_icon => $brand_icon) {
        $DB->update(
            'glpi_plugin_sso_idps',
            ['icon' => $brand_icon],
            ['icon' => $old_icon]
        );
    }

    // Tablas nuevas de versiones futuras: re-correr el SQL (IF NOT EXISTS).
    $DB->runFile(Plugin::getPhpDir('sso') . '/sql/install.sql');
}

/**
 * Hook display_login: botones "Iniciar sesión con <IdP>", forced SSO con
 * bypass ?noSSO=1 y HRD por dominio (columna derecha del form, spike M0 #3).
 */
function plugin_sso_display_login(): void
{
    $idps = \GlpiPlugin\Sso\Idp::getActive();
    if ($idps === []) {
        return;
    }

    $cfg  = \GlpiPlugin\Sso\Config::get();
    $base = '/plugins/sso/front/login.php?idp=';
    echo "<link rel='stylesheet' href='/plugins/sso/public/login.css?v="
        . rawurlencode(PLUGIN_SSO_VERSION) . "'>";

    // Single Logout (M4): la sesión GLPI murió pero quedó el hint del IdP →
    // cerrar también la sesión del IdP y volver. Corre antes que el forced
    // SSO (si no, el auto-redirect re-loguearía al usuario que se deslogueó).
    if (
        (int) $cfg['idp_logout'] === 1
        && ($_COOKIE['sso_lt'] ?? '') !== ''
        && !Session::getLoginUserID()
    ) {
        $logout_url = '/plugins/sso/front/logout.php';
        echo Html::scriptBlock('window.location.replace(' . json_encode($logout_url) . ');');
        return;
    }

    // Bypass de emergencia: ?noSSO=1 desactiva el auto-redirect 5 minutos.
    $bypass = isset($_GET['noSSO']) || (($_COOKIE['sso_bypass'] ?? '') === '1');
    if (isset($_GET['noSSO'])) {
        echo Html::scriptBlock("document.cookie = 'sso_bypass=1; max-age=300; path=/';");
    }

    // Forced SSO: auto-redirect al IdP default (los botones quedan como
    // fallback para browsers sin JS).
    if (!$bypass && (int) $cfg['forced_sso'] === 1 && (int) $cfg['default_idps_id'] > 0) {
        echo Html::scriptBlock('window.location.replace(' . json_encode($base . (int) $cfg['default_idps_id']) . ');');
    }

    $button_items = [];
    $icon_items   = [];
    foreach ($idps as $row) {
        $provider_name = trim((string) $row['button_label']) !== ''
            ? $row['button_label']
            : $row['name'];
        $label = sprintf(__('Log in with %s', 'sso'), $provider_name);
        $url  = $base . (int) $row['id'];
        $icon = trim((string) $row['icon']) !== '' ? $row['icon'] : 'ti ti-login';
        $presentation = ($row['login_presentation'] ?? 'button') === 'icon' ? 'icon' : 'button';
        $icon_html = \GlpiPlugin\Sso\Idp::renderProviderIcon($icon);
        if ($presentation === 'icon') {
            $icon_items[] = "<a class='sso-login-provider-icon' href='"
                . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . "' aria-label='"
                . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . "' title='"
                . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . "'>"
                . $icon_html . "</a>";
            continue;
        }
        $button_items[] = "<a class='sso-login-provider' href='"
            . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . "' aria-label='"
            . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . "'>"
            . "<span class='sso-login-provider-mark'>" . $icon_html . "</span>"
            . "<span class='sso-login-provider-copy'><span class='sso-login-provider-name'>"
            . htmlspecialchars($provider_name, ENT_QUOTES, 'UTF-8') . "</span></span>"
            . "<i class='ti ti-chevron-right sso-login-provider-arrow' aria-hidden='true'></i></a>";
    }

    echo "<section class='sso-login-panel' aria-labelledby='sso-login-title'>";
    echo "<div class='sso-login-divider' role='separator'><span>"
        . htmlspecialchars(__('or continue with', 'sso'), ENT_QUOTES, 'UTF-8') . "</span></div>";
    echo "<div class='sso-login-header'><span class='sso-login-header-icon' aria-hidden='true'>"
        . "<i class='ti ti-shield-lock'></i></span><div><h2 id='sso-login-title'>"
        . htmlspecialchars(__('Single sign-on', 'sso'), ENT_QUOTES, 'UTF-8') . "</h2><p>"
        . htmlspecialchars(__('Use your organization account', 'sso'), ENT_QUOTES, 'UTF-8')
        . "</p></div></div>";
    if ($button_items !== []) {
        echo "<div class='sso-login-provider-list'>" . implode('', $button_items) . "</div>";
    }
    if ($icon_items !== []) {
        echo "<div class='sso-login-icon-list' role='group' aria-label='"
            . htmlspecialchars(
                _n('Identity provider', 'Identity providers', count($icon_items), 'sso'),
                ENT_QUOTES,
                'UTF-8'
            ) . "'>"
            . implode('', $icon_items) . "</div>";
    }

    // HRD: dominio del email → IdP (sale de domain_allowlist; resolución
    // client-side, el email nunca viaja en una URL).
    if ((int) $cfg['hrd_enabled'] === 1) {
        $map = [];
        foreach ($idps as $row) {
            foreach (explode(',', (string) $row['domain_allowlist']) as $domain) {
                $domain = strtolower(trim($domain));
                if ($domain !== '') {
                    $map[$domain] = (int) $row['id'];
                }
            }
        }
        if ($map !== []) {
            echo "<div class='sso-login-hrd'>";
            echo "<input type='email' id='sso-hrd-email' class='form-control' placeholder='"
                . htmlspecialchars(__('your.email@company.com', 'sso'), ENT_QUOTES, 'UTF-8') . "'>";
            echo "<button type='button' class='btn btn-primary' onclick='ssoHrdGo()'>"
                . htmlspecialchars(__('Continue with SSO', 'sso'), ENT_QUOTES, 'UTF-8') . "</button>";
            echo "</div>";
            echo Html::scriptBlock('
                var ssoHrdMap = ' . json_encode($map) . ';
                var ssoHrdBase = ' . json_encode($base) . ';
                function ssoHrdGo() {
                    var v = (document.getElementById("sso-hrd-email").value || "").toLowerCase();
                    var at = v.lastIndexOf("@");
                    var d = at >= 0 ? v.slice(at + 1) : v;
                    if (ssoHrdMap[d]) {
                        window.location = ssoHrdBase + ssoHrdMap[d];
                    } else {
                        alert(' . json_encode(__('No SSO configured for this domain, please use the local login form', 'sso')) . ');
                    }
                }
            ');
        }
    }

    echo "</section>";
}

function plugin_sso_uninstall(): bool
{
    global $DB;

    CronTask::unregister('sso');

    foreach (plugin_sso_tables() as $table) {
        if ($DB->tableExists($table)) {
            $DB->dropTable($table);
        }
    }

    // Itemtypes exactos (nada de LIKE '%Sso%': matchearía samlSSO ajeno).
    $itemtypes = [
        'GlpiPlugin\\Sso\\Idp',
        'GlpiPlugin\\Sso\\Log',
        'PluginSsoRuleAuth',
    ];
    foreach (['glpi_displaypreferences', 'glpi_logs'] as $glpi_table) {
        $DB->delete($glpi_table, ['itemtype' => $itemtypes]);
    }
    $DB->delete('glpi_profilerights', ['name' => 'plugin_sso']);

    // Config global guardada en glpi_configs (contexto plugin:sso).
    $DB->delete('glpi_configs', ['context' => Config::CONTEXT]);

    // Reglas del engine nativo (sub_type namespaced; el alias por las dudas).
    $rule_ids = [];
    foreach ($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_rules',
        'WHERE' => ['sub_type' => ['GlpiPlugin\\Sso\\RuleAuth', 'PluginSsoRuleAuth']]]) as $row) {
        $rule_ids[] = (int) $row['id'];
    }
    if ($rule_ids !== []) {
        $DB->delete('glpi_rulecriterias', ['rules_id' => $rule_ids]);
        $DB->delete('glpi_ruleactions', ['rules_id' => $rule_ids]);
        $DB->delete('glpi_rules', ['id' => $rule_ids]);
    }

    return true;
}

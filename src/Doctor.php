<?php

namespace GlpiPlugin\Sso;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Diagnóstico operativo del plugin: estado de DB/crons/config/IdPs con
 * probes opcionales de red (discovery/JWKS/metadata). Devuelve datos, no
 * imprime: lo consumen el comando `plugins:sso:doctor` y front/doctor.php.
 *
 * El support bundle es REDACTADO por construcción: nunca selecciona
 * columnas de secretos/tokens ni el message/details/ip de los logs.
 */
class Doctor
{
    public const OK   = 'ok';
    public const WARN = 'warn';
    public const FAIL = 'fail';

    private const TABLES = [
        'glpi_plugin_sso_idps',
        'glpi_plugin_sso_requeststates',
        'glpi_plugin_sso_userlinks',
        'glpi_plugin_sso_scimgroups',
        'glpi_plugin_sso_logs',
        'glpi_plugin_sso_profiles',
    ];

    private const HTTP_TIMEOUT = 5;

    /**
     * Corre todos los chequeos.
     *
     * @param bool $with_network incluir probes HTTP a los IdPs
     * @return array<int, array{section: string, name: string, status: string, detail: string}>
     */
    public static function run(bool $with_network = true): array
    {
        $checks = [];
        $add = function (string $section, string $name, string $status, string $detail = '') use (&$checks): void {
            $checks[] = ['section' => $section, 'name' => $name, 'status' => $status, 'detail' => $detail];
        };

        self::checkCore($add);
        self::checkTables($add);
        self::checkConfig($add);
        self::checkCrons($add);
        self::checkIdps($add, $with_network);

        return $checks;
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkCore(callable $add): void
    {
        global $DB;

        $row = null;
        foreach ($DB->request(['FROM' => 'glpi_plugins', 'WHERE' => ['directory' => 'sso']]) as $r) {
            $row = $r;
        }
        if ($row === null) {
            $add('core', 'Registro del plugin', self::FAIL, 'sin fila en glpi_plugins');
        } else {
            $state_ok = ((int) $row['state']) === 1;
            $add(
                'core',
                'Registro del plugin',
                $state_ok ? self::OK : self::FAIL,
                'version ' . $row['version'] . ', state ' . $row['state']
                    . ($row['version'] !== PLUGIN_SSO_VERSION ? ' (código: ' . PLUGIN_SSO_VERSION . ' — correr plugin:install --force)' : '')
            );
        }

        $add(
            'core',
            'PHP',
            version_compare(PHP_VERSION, '8.2.0', 'ge') ? self::OK : self::FAIL,
            PHP_VERSION
        );
        $missing = array_filter(
            ['openssl', 'curl', 'dom', 'json', 'mbstring'],
            static fn (string $e): bool => !extension_loaded($e)
        );
        $add(
            'core',
            'Extensiones PHP',
            $missing === [] ? self::OK : self::FAIL,
            $missing === [] ? 'openssl curl dom json mbstring' : 'faltan: ' . implode(', ', $missing)
        );
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkTables(callable $add): void
    {
        global $DB;

        $missing = array_filter(self::TABLES, static fn (string $t): bool => !$DB->tableExists($t));
        $add(
            'db',
            'Tablas del plugin',
            $missing === [] ? self::OK : self::FAIL,
            $missing === [] ? count(self::TABLES) . ' tablas presentes' : 'faltan: ' . implode(', ', $missing)
        );
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkConfig(callable $add): void
    {
        $base = Config::baseUrl();
        $add(
            'config',
            'Base URL del SSO',
            $base !== '' ? self::OK : self::WARN,
            $base !== '' ? $base : 'sin configurar: se usa url_base del core'
        );

        $forced = (int) Config::value('forced_sso');
        $add(
            'config',
            'Forced SSO',
            self::OK,
            $forced ? 'activo (bypass: ?noSSO=1)' : 'inactivo (login local visible)'
        );
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkCrons(callable $add): void
    {
        global $DB;

        $found = [];
        $it = $DB->request([
            'FROM'  => 'glpi_crontasks',
            // Registrados bajo el alias legacy; el nombre canónico por si
            // alguna instalación futura los migra.
            'WHERE' => ['itemtype' => ['PluginSsoCron', 'GlpiPlugin\\Sso\\Cron']],
        ]);
        foreach ($it as $row) {
            $found[$row['name']] = $row;
        }

        foreach (['purgestate', 'purgelogs', 'certwatch'] as $name) {
            if (!isset($found[$name])) {
                $add('cron', "Cron $name", self::FAIL, 'no registrado');
                continue;
            }
            $row     = $found[$name];
            $enabled = ((int) $row['state']) !== 0; // 0 = disabled
            $lastrun = (string) ($row['lastrun'] ?? '');
            $stale   = false;
            if ($lastrun !== '') {
                $age   = time() - (int) strtotime($lastrun);
                $stale = $age > 2 * (int) $row['frequency'];
            }
            // "nunca corrió" es sospechoso (modo interno con cron externo,
            // scheduler caído): WARN, no OK.
            $status = (!$enabled || $stale || $lastrun === '') ? self::WARN : self::OK;
            $add(
                'cron',
                "Cron $name",
                $status,
                ($enabled ? 'habilitado' : 'DESHABILITADO')
                    . ', última corrida: ' . ($lastrun !== '' ? $lastrun . ($stale ? ' (atrasada)' : '') : 'NUNCA')
            );
        }
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkIdps(callable $add, bool $with_network): void
    {
        global $DB;

        $count = 0;
        foreach ($DB->request(['FROM' => 'glpi_plugin_sso_idps']) as $row) {
            $count++;
            $label = 'IdP #' . $row['id'] . ' ' . $row['name'];
            if (!(int) $row['is_active']) {
                $add('idp', $label, self::WARN, 'inactivo');
                continue;
            }

            if ($row['protocol'] === Idp::PROTO_SAML) {
                self::checkSamlIdp($add, $label, $row);
            } else {
                self::checkOidcIdp($add, $label, $row, $with_network);
            }

            self::checkIdpActivity($add, $label, (int) $row['id']);
        }

        if ($count === 0) {
            $add('idp', 'Proveedores', self::WARN, 'no hay IdPs configurados');
        }
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkSamlIdp(callable $add, string $label, array $row): void
    {
        $cert = (string) ($row['idp_x509cert'] ?? '');
        if ($cert === '') {
            $add('idp', "$label — cert IdP", self::FAIL, 'SAML sin certificado del IdP');
            return;
        }
        $days = CertWatch::daysUntilExpiration($cert);
        if ($days === null) {
            $add('idp', "$label — cert IdP", self::FAIL, 'certificado no parseable');
        } else {
            $status = $days < 0 ? self::FAIL : ($days < 30 ? self::WARN : self::OK);
            $add('idp', "$label — cert IdP", $status, "vence en $days días (" . CertWatch::expirationDate($cert) . ')');
        }

        $sp_cert = (string) ($row['sp_x509cert'] ?? '');
        if ($sp_cert !== '') {
            $days = CertWatch::daysUntilExpiration($sp_cert);
            if ($days !== null) {
                $status = $days < 0 ? self::FAIL : ($days < 30 ? self::WARN : self::OK);
                $add('idp', "$label — cert SP", $status, "vence en $days días");
            }
        }
    }

    /** @param callable(string,string,string,string):void $add */
    private static function checkOidcIdp(callable $add, string $label, array $row, bool $with_network): void
    {
        $issuer = rtrim((string) ($row['issuer_url'] ?? ''), '/');
        if ($issuer === '') {
            $add('idp', "$label — OIDC", self::FAIL, 'sin issuer URL');
            return;
        }
        if (!str_starts_with($issuer, 'https://') && !self::isPrivateHost($issuer)) {
            $add('idp', "$label — issuer", self::WARN, 'issuer sin HTTPS: ' . $issuer);
        }

        if (($row['client_secret'] ?? null) === null || $row['client_secret'] === '') {
            $add('idp', "$label — client_secret", self::WARN, 'sin secreto guardado (¿cliente público?)');
        }

        if ($with_network) {
            [$code, $ms, $err] = self::http($issuer . '/.well-known/openid-configuration');
            $status = $code === 200 ? self::OK : self::FAIL;
            $add('idp', "$label — discovery", $status, $code === 200 ? "200 en {$ms}ms" : trim("HTTP $code $err"));

            $cache = json_decode((string) ($row['discovery_cache'] ?? ''), true);
            $jwks_uri = is_array($cache) ? (string) ($cache['jwks_uri'] ?? '') : '';
            if ($jwks_uri !== '') {
                [$code, $ms, $err] = self::http($jwks_uri);
                $status = $code === 200 ? self::OK : self::FAIL;
                $add('idp', "$label — JWKS", $status, $code === 200 ? "200 en {$ms}ms" : trim("HTTP $code $err"));
            }
        }

        if ((int) ($row['scim_enabled'] ?? 0) === 1) {
            $has_token = ($row['scim_token_hash'] ?? '') !== '';
            $add('idp', "$label — SCIM", $has_token ? self::OK : self::WARN, $has_token ? 'habilitado, token configurado' : 'habilitado SIN token');
        }
    }

    /** Último éxito y último error de auth del IdP. */
    private static function checkIdpActivity(callable $add, string $label, int $idps_id): void
    {
        global $DB;

        $last = static function (array $where) use ($DB, $idps_id): string {
            $it = $DB->request([
                'SELECT' => ['event', 'date'],
                'FROM'   => 'glpi_plugin_sso_logs',
                'WHERE'  => array_merge(['idps_id' => $idps_id], $where),
                'ORDER'  => 'id DESC',
                'LIMIT'  => 1,
            ]);
            foreach ($it as $row) {
                return $row['event'] . ' @ ' . $row['date'];
            }
            return '';
        };

        $ok  = $last(['event' => 'login_ok']);
        $err = $last(['level' => 'error']);
        $add(
            'idp',
            "$label — actividad",
            self::OK,
            'último login: ' . ($ok !== '' ? $ok : 'nunca')
                . '; último error: ' . ($err !== '' ? $err : 'ninguno')
        );
    }

    /**
     * Support bundle REDACTADO: apto para adjuntar a un ticket de soporte.
     * Nunca incluye secretos, tokens, assertions, session IDs, mensajes de
     * log (pueden traer emails) ni IPs.
     */
    public static function bundle(bool $with_network = true): array
    {
        global $DB;

        $idps = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'name', 'protocol', 'is_active', 'issuer_url', 'idp_x509cert', 'scim_enabled', 'login_presentation'],
            'FROM'   => 'glpi_plugin_sso_idps',
        ]) as $row) {
            $cert = (string) ($row['idp_x509cert'] ?? '');
            $idps[] = [
                'id'               => (int) $row['id'],
                'name'             => $row['name'],
                'protocol'         => $row['protocol'],
                'active'           => (bool) $row['is_active'],
                'issuer'           => $row['issuer_url'],
                'cert_expiration'  => $cert !== '' ? CertWatch::expirationDate($cert) : null,
                'cert_fingerprint' => $cert !== '' ? self::certFingerprint($cert) : null,
                'scim_enabled'     => (bool) ($row['scim_enabled'] ?? false),
            ];
        }

        $events = [];
        foreach ($DB->request([
            'SELECT' => ['date', 'idps_id', 'event', 'level'],
            'FROM'   => 'glpi_plugin_sso_logs',
            'ORDER'  => 'id DESC',
            'LIMIT'  => 20,
        ]) as $row) {
            $events[] = $row;
        }

        return [
            'generated_at'   => date('c'),
            'glpi_version'   => GLPI_VERSION,
            'php_version'    => PHP_VERSION,
            'plugin_version' => PLUGIN_SSO_VERSION,
            'checks'         => self::run($with_network),
            'idps'           => $idps,
            'recent_events'  => $events,
        ];
    }

    private static function certFingerprint(string $pem): ?string
    {
        if (!str_contains($pem, 'BEGIN CERTIFICATE')) {
            $pem = "-----BEGIN CERTIFICATE-----\n"
                . chunk_split(preg_replace('/\s+/', '', $pem), 64, "\n")
                . "-----END CERTIFICATE-----\n";
        }
        $fp = openssl_x509_fingerprint($pem, 'sha256');
        return $fp === false ? null : $fp;
    }

    /**
     * ¿El host de la URL es privado/loopback? (para no exigir HTTPS en labs).
     * Puro y unit-testeado: rangos RFC1918 + loopback/reservados vía
     * FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE, más localhost literal.
     */
    public static function isPrivateHost(string $url): bool
    {
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        if ($host === '') {
            return false;
        }
        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            return false; // hostname público: exigir HTTPS
        }
        return filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /** @return array{0: int, 1: int, 2: string} [http_code, ms, error] */
    private static function http(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::HTTP_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'glpi-sso-doctor/' . PLUGIN_SSO_VERSION,
        ]);
        $start = microtime(true);
        curl_exec($ch);
        $ms   = (int) round((microtime(true) - $start) * 1000);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err  = (string) curl_error($ch);
        curl_close($ch);
        return [$code, $ms, $err];
    }
}

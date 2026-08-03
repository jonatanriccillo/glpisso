<?php

namespace GlpiPlugin\Sso;

use CommonDBTM;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Estado de flujo pendiente en DB (nunca en sesión PHP: el POST del ACS es
 * cross-site y SameSite no deja viajar la cookie). Cuatro usos:
 *  - oidc_state:   state+nonce+PKCE emitidos al redirigir al IdP
 *  - saml_request: ID del AuthnRequest emitido (validación InResponseTo)
 *  - saml_replay:  cache anti-replay de assertion IDs ya vistos
 *  - login_ticket: ticket one-shot ACS/callback → finish.php
 * TTL corto SIEMPRE + purga por cron (lección glpisaml/loginstates).
 */
class RequestState extends CommonDBTM
{
    public static $rightname = 'plugin_sso';

    public const KIND_OIDC_STATE   = 'oidc_state';
    public const KIND_SAML_REQUEST = 'saml_request';
    public const KIND_SAML_REPLAY  = 'saml_replay';
    public const KIND_LOGIN_TICKET = 'login_ticket';
    public const KIND_LOGOUT_HINT  = 'logout_hint';

    public const FLOW_TTL   = 600;   // seg: ida y vuelta al IdP
    public const TICKET_TTL = 60;    // seg: redirect ACS/callback → finish
    public const HINT_TTL   = 86400; // seg: datos para el Single Logout

    public static function getTypeName($nb = 0): string
    {
        return __('SSO pending request', 'sso');
    }

    public static function newToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /** Persiste un token de flujo con su payload. Devuelve false si falló. */
    public static function stash(string $kind, string $token, int $idps_id, array $payload, int $ttl_seconds): bool
    {
        global $DB;

        try {
            return (bool) $DB->insert(self::getTable(), [
                'kind'       => $kind,
                'token'      => $token,
                'idps_id'    => $idps_id,
                'payload'    => json_encode($payload, JSON_UNESCAPED_SLASHES),
                'expires_at' => date('Y-m-d H:i:s', time() + $ttl_seconds),
            ]);
        } catch (\Throwable $e) {
            Log::record('error_state', Log::LEVEL_ERROR, 'stash failed: ' . $e->getMessage(), ['idps_id' => $idps_id]);
            return false;
        }
    }

    /**
     * Consume un token one-shot: devuelve ['idps_id' => int, ...payload] o
     * null si no existe, expiró o ya fue consumido (carrera: gana el que
     * logra el DELETE).
     */
    public static function consume(string $kind, string $token): ?array
    {
        global $DB;

        if ($token === '') {
            return null;
        }

        $row = null;
        foreach ($DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => ['kind' => $kind, 'token' => $token],
            'LIMIT' => 1,
        ]) as $r) {
            $row = $r;
        }
        if ($row === null) {
            return null;
        }

        // Single-use: si otro request ya lo borró, affected = 0 y se rechaza.
        $DB->delete(self::getTable(), ['id' => (int) $row['id']]);
        if ($DB->affectedRows() !== 1) {
            return null;
        }

        if (strtotime((string) $row['expires_at']) < time()) {
            return null;
        }

        $payload = json_decode((string) $row['payload'], true);
        if (!is_array($payload)) {
            $payload = [];
        }
        $payload['idps_id'] = (int) $row['idps_id'];
        return $payload;
    }

    /**
     * Cache anti-replay: registra el ID y devuelve true si YA se había visto
     * (la unique (kind, token) hace de candado atómico).
     */
    public static function seen(string $kind, string $token, int $idps_id, int $ttl_seconds): bool
    {
        global $DB;

        try {
            $DB->insert(self::getTable(), [
                'kind'       => $kind,
                'token'      => $token,
                'idps_id'    => $idps_id,
                'payload'    => null,
                'expires_at' => date('Y-m-d H:i:s', time() + $ttl_seconds),
            ]);
            return false;
        } catch (\Throwable $e) {
            return true; // duplicate key => replay
        }
    }

    /** @return int filas purgadas */
    public static function purgeExpired(): int
    {
        global $DB;

        $DB->delete(self::getTable(), ['expires_at' => ['<', date('Y-m-d H:i:s')]]);
        return max(0, (int) $DB->affectedRows());
    }
}

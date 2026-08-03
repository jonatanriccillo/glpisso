<?php

namespace GlpiPlugin\Sso;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Html;
use RuntimeException;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Relying Party OIDC: Authorization Code + PKCE (S256), siempre.
 * Flujo propio con estado en DB (RequestState) — mismo camino ticket→finish
 * que SAML — y validación criptográfica del ID token vía firebase/php-jwt.
 *
 * Validaciones (BLUEPRINT §8): alg whitelist (jamás none/HS*), firma contra
 * JWKS con refresh ante kid desconocido, iss exacto del discovery, aud ==
 * client_id (+ azp si hay múltiples), exp/iat con skew, nonce contra el
 * emitido. `email_verified` lo exige el pipeline según config del IdP.
 */
class OidcClient
{
    private const CLOCK_SKEW   = 90;   // segundos
    private const HTTP_TIMEOUT = 10;   // segundos
    private const CACHE_TTL    = 3600; // discovery/JWKS
    private const ALLOWED_ALGS = ['RS256', 'ES256'];

    private Idp $idp;

    public function __construct(Idp $idp)
    {
        SamlClient::loadVendor();
        $this->idp = $idp;
    }

    /** La redirect_uri única del plugin (se registra en el IdP). */
    public static function redirectUri(): string
    {
        return Config::baseUrl() . '/plugins/sso/front/callback.php';
    }

    /** Arma el authorize request, persiste el estado y redirige. No retorna. */
    public function startLogin(string $redirect): void
    {
        $conf = $this->discover();

        $state     = RequestState::newToken();
        $nonce     = RequestState::newToken();
        $verifier  = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $ok = RequestState::stash(RequestState::KIND_OIDC_STATE, $state, (int) $this->idp->getID(), [
            'nonce'    => $nonce,
            'verifier' => $verifier,
            'redirect' => $redirect,
        ], RequestState::FLOW_TTL);
        if (!$ok) {
            throw new RuntimeException('could not persist OIDC state');
        }

        $scopes = trim((string) $this->idp->fields['scopes']);
        $params = [
            'response_type'         => 'code',
            'client_id'             => (string) $this->idp->fields['client_id'],
            'redirect_uri'          => self::redirectUri(),
            'scope'                 => $scopes !== '' ? $scopes : 'openid profile email',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $challenge,
            'code_challenge_method' => 'S256',
        ];

        $auth_url = (string) $conf['authorization_endpoint'];
        $auth_url .= (str_contains($auth_url, '?') ? '&' : '?') . http_build_query($params);
        Html::redirect($auth_url);
    }

    /**
     * Procesa el retorno del IdP (GET). Resuelve el IdP vía el state one-shot.
     *
     * @return array{0: Idp, 1: Identity, 2: string, 3: array} [idp, identity, redirect, session_hint]
     * @throws RuntimeException si cualquier validación falla (fail-closed)
     */
    public static function handleCallback(): array
    {
        if (isset($_GET['error'])) {
            throw new RuntimeException('IdP returned error: ' . $_GET['error']
                . ' — ' . (string) ($_GET['error_description'] ?? ''));
        }

        $state = (string) ($_GET['state'] ?? '');
        $code  = (string) ($_GET['code'] ?? '');
        if ($code === '') {
            throw new RuntimeException('callback without authorization code');
        }

        $st = RequestState::consume(RequestState::KIND_OIDC_STATE, $state);
        if ($st === null) {
            throw new RuntimeException('unsolicited, expired or replayed OIDC callback (no state)');
        }

        $idp = new Idp();
        if (
            !$idp->getFromDB((int) $st['idps_id'])
            || !(bool) $idp->fields['is_active']
            || (bool) $idp->fields['is_deleted']
            || $idp->fields['protocol'] !== Idp::PROTO_OIDC
        ) {
            throw new RuntimeException('identity provider unavailable for this callback');
        }

        $client = new self($idp);
        $conf   = $client->discover();

        // Intercambio de código (con PKCE; client_secret sólo si hay).
        $post = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => self::redirectUri(),
            'client_id'     => (string) $idp->fields['client_id'],
            'code_verifier' => (string) ($st['verifier'] ?? ''),
        ];
        $secret = $idp->getSecret('client_secret');
        if ($secret !== '') {
            $post['client_secret'] = $secret;
        }
        $tokens = self::http((string) $conf['token_endpoint'], $post);

        $id_token = (string) ($tokens['id_token'] ?? '');
        if ($id_token === '') {
            throw new RuntimeException('token response without id_token');
        }

        $payload = $client->validateIdToken($id_token, $conf, (string) ($st['nonce'] ?? ''));
        $claims  = json_decode(json_encode($payload), true);

        $subject = (string) ($claims['sub'] ?? '');
        if ($subject === '') {
            throw new RuntimeException('id_token without sub');
        }

        // userinfo sólo si falta el email en el id_token (y verificando sub).
        if (
            trim((string) ($claims['email'] ?? '')) === ''
            && !empty($conf['userinfo_endpoint'])
            && !empty($tokens['access_token'])
        ) {
            try {
                $ui = self::http((string) $conf['userinfo_endpoint'], null, (string) $tokens['access_token']);
                if ((string) ($ui['sub'] ?? '') === $subject) {
                    $claims += $ui;
                }
            } catch (\Throwable $e) {
                Log::debug('oidc_userinfo', 'userinfo fetch failed: ' . $e->getMessage(),
                    ['idps_id' => (int) $idp->getID()]);
            }
        }

        $email = trim((string) ($claims['email'] ?? ''));
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $email = '';
        }
        $verified = array_key_exists('email_verified', $claims)
            ? filter_var($claims['email_verified'], FILTER_VALIDATE_BOOLEAN)
            : null;

        $identity = new Identity($subject, $claims, $email, $verified);

        // id_token para el RP-initiated logout (id_token_hint, M4).
        $session = ['id_token' => $id_token];

        return [$idp, $identity, (string) ($st['redirect'] ?? ''), $session];
    }

    /** URL de RP-initiated logout, o null si el IdP no publica end_session. */
    public function logoutUrl(array $hint): ?string
    {
        $conf = $this->discover();
        $end  = (string) ($conf['end_session_endpoint'] ?? '');
        if ($end === '') {
            return null;
        }

        $params = [
            'post_logout_redirect_uri' => Config::baseUrl() . '/index.php?noAUTO=1',
            'client_id'                => (string) $this->idp->fields['client_id'],
        ];
        if (($hint['id_token'] ?? '') !== '') {
            $params['id_token_hint'] = (string) $hint['id_token'];
        }
        return $end . (str_contains($end, '?') ? '&' : '?') . http_build_query($params);
    }

    /** @throws RuntimeException */
    private function validateIdToken(string $jwt, array $conf, string $expected_nonce): \stdClass
    {
        try {
            $payload = self::decodeWithKeys($jwt, $this->jwks(false));
        } catch (\Firebase\JWT\SignatureInvalidException | \UnexpectedValueException $e) {
            // kid desconocido (rotación de claves) → un único refetch del JWKS.
            $payload = self::decodeWithKeys($jwt, $this->jwks(true));
        }

        return self::validateClaims(
            $payload,
            $conf,
            (string) $this->idp->fields['client_id'],
            $expected_nonce
        );
    }

    /**
     * Núcleo criptográfico puro (unit-testeable): whitelist de alg + firma
     * contra un JWKS dado + exp/iat con skew. No toca red ni DB.
     *
     * @throws RuntimeException|\UnexpectedValueException
     */
    public static function decodeWithKeys(string $jwt, array $jwks): \stdClass
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new RuntimeException('malformed id_token');
        }
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
        $alg    = (string) ($header['alg'] ?? '');
        if (!in_array($alg, self::ALLOWED_ALGS, true)) {
            throw new RuntimeException('disallowed id_token alg: ' . ($alg !== '' ? $alg : '(none)'));
        }

        JWT::$leeway = self::CLOCK_SKEW;
        return JWT::decode($jwt, JWK::parseKeySet($jwks, $alg));
    }

    /**
     * Validación pura de claims de un id_token YA verificado
     * criptográficamente: iss exacto, aud == client_id (+ azp si hay
     * múltiples audiences) y nonce contra el emitido (nunca vacío).
     *
     * @throws RuntimeException
     */
    public static function validateClaims(
        \stdClass $payload,
        array $conf,
        string $client_id,
        string $expected_nonce
    ): \stdClass {
        if ((string) ($payload->iss ?? '') !== (string) $conf['issuer']) {
            throw new RuntimeException('issuer mismatch: ' . (string) ($payload->iss ?? ''));
        }

        $auds = is_array($payload->aud ?? null) ? $payload->aud : [(string) ($payload->aud ?? '')];
        if (!in_array($client_id, array_map('strval', $auds), true)) {
            throw new RuntimeException('audience mismatch');
        }
        if (count($auds) > 1 && (string) ($payload->azp ?? '') !== $client_id) {
            throw new RuntimeException('azp mismatch on multi-audience token');
        }

        if ((string) ($payload->nonce ?? '') !== $expected_nonce || $expected_nonce === '') {
            throw new RuntimeException('nonce mismatch');
        }

        return $payload;
    }

    /**
     * Documento de discovery, cacheado en la fila del IdP (TTL 1 h).
     *
     * @throws RuntimeException
     */
    public function discover(bool $force = false): array
    {
        if (!$force) {
            $cached = $this->cached('discovery');
            if ($cached !== null) {
                return $cached;
            }
        }

        $issuer = rtrim((string) $this->idp->fields['issuer_url'], '/');
        if ($issuer === '') {
            throw new RuntimeException('issuer URL not configured');
        }

        $conf = self::http($issuer . '/.well-known/openid-configuration');
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $key) {
            if (empty($conf[$key])) {
                throw new RuntimeException('discovery document missing ' . $key);
            }
        }
        // El spec exige match exacto issuer configurado ↔ anunciado.
        if (rtrim((string) $conf['issuer'], '/') !== $issuer) {
            throw new RuntimeException('discovery issuer mismatch: ' . (string) $conf['issuer']);
        }

        $this->cache('discovery', $conf);
        return $conf;
    }

    /** @throws RuntimeException */
    private function jwks(bool $force): array
    {
        if (!$force) {
            $cached = $this->cached('jwks');
            if ($cached !== null) {
                return $cached;
            }
        }

        $conf = $this->discover($force);
        $jwks = self::http((string) $conf['jwks_uri']);
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new RuntimeException('JWKS without keys');
        }

        $this->cache('jwks', $jwks);
        return $jwks;
    }

    private function cached(string $what): ?array
    {
        $at  = strtotime((string) ($this->idp->fields[$what . '_cached_at'] ?? '')) ?: 0;
        $raw = (string) ($this->idp->fields[$what . '_cache'] ?? '');
        if ($raw === '' || time() - $at >= self::CACHE_TTL) {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    private function cache(string $what, array $data): void
    {
        global $DB;

        $encoded = json_encode($data, JSON_UNESCAPED_SLASHES);
        $now     = date('Y-m-d H:i:s');
        $DB->update(Idp::getTable(), [
            $what . '_cache'     => $encoded,
            $what . '_cached_at' => $now,
        ], ['id' => (int) $this->idp->getID()]);
        $this->idp->fields[$what . '_cache']     = $encoded;
        $this->idp->fields[$what . '_cached_at'] = $now;
    }

    /**
     * HTTP hacia el IdP: GET (con Bearer opcional) o POST form. Espera JSON.
     *
     * @throws RuntimeException
     */
    private static function http(string $url, ?array $post = null, string $bearer = ''): array
    {
        $headers = ['Accept: application/json'];
        if ($bearer !== '') {
            $headers[] = 'Authorization: Bearer ' . $bearer;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::HTTP_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER     => $headers,
        ]);
        if ($post !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $body   = curl_exec($ch);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($body === false || $errno !== 0) {
            throw new RuntimeException('HTTP error talking to IdP: ' . $error);
        }
        if ($status >= 400) {
            throw new RuntimeException('IdP returned HTTP ' . $status . ': ' . substr((string) $body, 0, 200));
        }
        $json = json_decode((string) $body, true);
        if (!is_array($json)) {
            throw new RuntimeException('IdP returned non-JSON response');
        }
        return $json;
    }
}

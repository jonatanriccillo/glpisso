<?php

namespace GlpiPlugin\Sso;

use Html;
use OneLogin\Saml2\Auth as OneLoginAuth;
use OneLogin\Saml2\IdPMetadataParser;
use OneLogin\Saml2\Settings as OneLoginSettings;
use Plugin;
use RuntimeException;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Wrapper de onelogin/php-saml (vendoreado). Nunca toca la DB salvo el estado
 * de flujo (RequestState). Flujo SP-initiated only:
 *   login.php → startLogin(): AuthnRequest + state en DB (token en RelayState)
 *   acs.php   → handleAcs(): valida Response + InResponseTo + replay → Identity
 */
class SamlClient
{
    private const CLOCK_SKEW = 90; // segundos

    private Idp $idp;

    public function __construct(Idp $idp)
    {
        self::loadVendor();
        $this->idp = $idp;
    }

    public static function loadVendor(): void
    {
        // __DIR__ y no Plugin::getPhpDir: mismo path y sin depender de GLPI
        // (los tests puros cargan esta clase sin core).
        require_once __DIR__ . '/../vendor/autoload.php';
    }

    /** URL pública del plugin (de la que derivan ACS/metadata). */
    private static function pluginBaseUrl(): string
    {
        return Config::baseUrl() . '/plugins/sso';
    }

    public static function spEntityId(int $idps_id): string
    {
        return self::pluginBaseUrl() . '/front/metadata.php?idp=' . $idps_id;
    }

    /** Settings de onelogin armados desde la fila del IdP. */
    private function buildSettings(): array
    {
        return self::settingsFromFields(
            $this->idp->fields,
            self::pluginBaseUrl(),
            $this->idp->getSecret('sp_private_key')
        );
    }

    /**
     * Núcleo puro (unit-testeable) del armado de settings de onelogin.
     * Acá vive la política de seguridad SAML del plugin: strict siempre,
     * firma de assertions requerida SIEMPRE, sin relajar destination, skew
     * acotado y rollover de certificados del IdP.
     */
    public static function settingsFromFields(array $f, string $base, string $sp_private_key): array
    {
        $idp_certs = [
            'x509cert' => (string) $f['idp_x509cert'],
        ];
        if (trim((string) $f['idp_x509cert_rollover']) !== '') {
            // Rotación: ambos certificados válidos para verificar firmas.
            $idp_certs = [
                'x509certMulti' => [
                    'signing'    => [(string) $f['idp_x509cert'], (string) $f['idp_x509cert_rollover']],
                    'encryption' => [(string) $f['idp_x509cert']],
                ],
            ];
        }

        return [
            'strict' => true,
            'debug'  => false,
            'sp' => [
                'entityId' => $base . '/front/metadata.php?idp=' . (int) $f['id'],
                'assertionConsumerService' => [
                    'url'     => $base . '/front/acs.php',
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],
                'NameIDFormat' => (string) $f['nameid_format'],
                'x509cert'     => trim((string) $f['sp_x509cert']),
                'privateKey'   => $sp_private_key,
            ],
            'idp' => array_merge([
                'entityId' => (string) $f['idp_entity_id'],
                'singleSignOnService' => [
                    'url'     => (string) $f['idp_sso_url'],
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                'singleLogoutService' => [
                    'url'     => (string) $f['idp_slo_url'],
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
            ], $idp_certs),
            'security' => [
                'authnRequestsSigned'    => (bool) $f['sign_authn_requests'],
                'wantAssertionsSigned'   => true,  // firma requerida SIEMPRE (§8)
                'wantAssertionsEncrypted' => (bool) $f['want_assertions_encrypted'],
                'wantNameId'             => true,
                'requestedAuthnContext'  => false,
                'relaxDestinationValidation' => false,
                'clockSkew'              => self::CLOCK_SKEW,
                // Keycloak emite un Attribute "Role" por cada rol (mismo Name
                // repetido); onelogin los mergea como multivaluado.
                'allowRepeatAttributeName' => true,
            ],
        ];
    }

    /** Emite el AuthnRequest, persiste el estado y redirige al IdP. No retorna. */
    public function startLogin(string $redirect): void
    {
        $auth  = new OneLoginAuth($this->buildSettings());
        $state = RequestState::newToken();

        // stay=true: devuelve la URL en vez de redirigir, así el estado se
        // persiste ANTES de mandar al usuario al IdP.
        $url = $auth->login($state, [], false, false, true);

        $ok = RequestState::stash(
            RequestState::KIND_SAML_REQUEST,
            $state,
            (int) $this->idp->getID(),
            ['request_id' => $auth->getLastRequestID(), 'redirect' => $redirect],
            RequestState::FLOW_TTL
        );
        if (!$ok) {
            throw new RuntimeException('could not persist SAML request state');
        }

        Html::redirect($url);
    }

    /**
     * Procesa el POST del ACS. Resuelve el IdP vía el token de RelayState
     * (one-shot en DB: un RelayState forjado o repetido consume en null).
     *
     * @return array{0: Idp, 1: Identity, 2: string, 3: array} [idp, identity, redirect, session_hint]
     * @throws RuntimeException si cualquier validación falla (fail-closed)
     */
    public static function handleAcs(): array
    {
        self::loadVendor();

        $relay = (string) ($_POST['RelayState'] ?? '');
        $state = RequestState::consume(RequestState::KIND_SAML_REQUEST, $relay);
        if ($state === null) {
            throw new RuntimeException('unsolicited, expired or replayed SAML response (no request state)');
        }

        $idp = new Idp();
        if (
            !$idp->getFromDB((int) $state['idps_id'])
            || !(bool) $idp->fields['is_active']
            || (bool) $idp->fields['is_deleted']
            || $idp->fields['protocol'] !== Idp::PROTO_SAML
        ) {
            throw new RuntimeException('identity provider unavailable for this response');
        }

        $client = new self($idp);
        $auth   = new OneLoginAuth($client->buildSettings());

        // Valida firma, condiciones, Destination, Audience e InResponseTo
        // contra el request emitido por login.php.
        $auth->processResponse((string) ($state['request_id'] ?? ''));

        if ($auth->getErrors() !== []) {
            throw new RuntimeException('SAML validation failed: ' . implode(', ', $auth->getErrors())
                . ' — ' . (string) $auth->getLastErrorReason());
        }
        if (!$auth->isAuthenticated()) {
            throw new RuntimeException('SAML response not authenticated');
        }

        // Anti-replay por assertion ID, con TTL hasta NotOnOrAfter + skew.
        $assertion_id = (string) $auth->getLastAssertionId();
        $not_on_or_after = $auth->getLastAssertionNotOnOrAfter();
        $ttl = max(60, (int) $not_on_or_after - time() + self::CLOCK_SKEW);
        if ($assertion_id === '' || RequestState::seen(RequestState::KIND_SAML_REPLAY, $assertion_id, (int) $idp->getID(), $ttl)) {
            throw new RuntimeException('replayed SAML assertion: ' . $assertion_id);
        }

        $subject = trim((string) $auth->getNameId());
        if ($subject === '') {
            throw new RuntimeException('SAML response has no NameID');
        }

        // Atributos + friendly names (sin pisar los nombres canónicos).
        $claims = $auth->getAttributes() + $auth->getAttributesWithFriendlyName();

        $identity = new Identity(
            $subject,
            $claims,
            self::resolveEmail($idp, $subject, $claims),
            null // SAML no informa verificación: se confía en el IdP firmante
        );

        // Datos de sesión del IdP para el Single Logout (M4).
        $session = [
            'nameid'        => $subject,
            'session_index' => (string) $auth->getSessionIndex(),
        ];

        return [$idp, $identity, (string) ($state['redirect'] ?? ''), $session];
    }

    /** SP-initiated SLO: LogoutRequest al IdP (redirect binding). No retorna. */
    public function startSlo(array $hint): void
    {
        if (trim((string) $this->idp->fields['idp_slo_url']) === '') {
            throw new RuntimeException('IdP has no SLO URL configured');
        }

        $auth  = new OneLoginAuth($this->buildSettings());
        $state = RequestState::newToken();

        $url = $auth->logout(
            $state, // RelayState: valida la LogoutResponse en sls.php
            [],
            ($hint['nameid'] ?? '') !== '' ? (string) $hint['nameid'] : null,
            ($hint['session_index'] ?? '') !== '' ? (string) $hint['session_index'] : null,
            true // stay: persistir el estado ANTES de redirigir
        );

        RequestState::stash(
            RequestState::KIND_SAML_REQUEST,
            $state,
            (int) $this->idp->getID(),
            ['slo_request_id' => $auth->getLastRequestID()],
            RequestState::FLOW_TTL
        );

        Log::record('logout', Log::LEVEL_INFO, 'SAML SLO started', ['idps_id' => (int) $this->idp->getID()]);
        Html::redirect($url);
    }

    /**
     * SLS: procesa la LogoutResponse (vuelta de nuestro SLO) o un
     * LogoutRequest IdP-initiated (front-channel). Devuelve la URL a la que
     * redirigir, o null para volver al login.
     *
     * @throws RuntimeException
     */
    public static function handleSls(): ?string
    {
        self::loadVendor();

        // Caso 1: LogoutResponse de un SLO iniciado por nosotros.
        if (isset($_GET['SAMLResponse'])) {
            $state = RequestState::consume(RequestState::KIND_SAML_REQUEST, (string) ($_GET['RelayState'] ?? ''));
            if ($state === null || !isset($state['slo_request_id'])) {
                throw new RuntimeException('unsolicited SAML LogoutResponse');
            }
            $idp = new Idp();
            if (!$idp->getFromDB((int) $state['idps_id']) || $idp->fields['protocol'] !== Idp::PROTO_SAML) {
                throw new RuntimeException('identity provider unavailable for this LogoutResponse');
            }
            $auth = new OneLoginAuth((new self($idp))->buildSettings());
            // La sesión GLPI ya murió antes de iniciar el SLO: keepLocalSession.
            $auth->processSLO(true, (string) $state['slo_request_id'], false, null, true);
            if ($auth->getErrors() !== []) {
                throw new RuntimeException('SLO validation failed: ' . implode(', ', $auth->getErrors()));
            }
            Log::record('logout', Log::LEVEL_INFO, 'SAML SLO completed', ['idps_id' => (int) $idp->getID()]);
            return null;
        }

        // Caso 2: LogoutRequest del IdP (otro SP cerró sesión).
        if (isset($_GET['SAMLRequest'])) {
            $idp = self::guessIdpForSls();
            if ($idp === null) {
                throw new RuntimeException('cannot determine IdP for incoming LogoutRequest');
            }
            $auth = new OneLoginAuth((new self($idp))->buildSettings());
            $url  = $auth->processSLO(false, null, false, static function (): void {
                \Session::cleanOnLogout();
            }, true);
            if ($auth->getErrors() !== []) {
                throw new RuntimeException('IdP-initiated SLO failed: ' . implode(', ', $auth->getErrors()));
            }
            Log::record('logout', Log::LEVEL_INFO, 'IdP-initiated SAML SLO processed', ['idps_id' => (int) $idp->getID()]);
            return is_string($url) && $url !== '' ? $url : null;
        }

        throw new RuntimeException('SLS called without a SAML message');
    }

    /** IdP del LogoutRequest entrante: hint del browser, o único SAML activo. */
    private static function guessIdpForSls(): ?Idp
    {
        $token = (string) ($_COOKIE['sso_lt'] ?? '');
        if ($token !== '') {
            $hint = RequestState::consume(RequestState::KIND_LOGOUT_HINT, $token);
            if ($hint !== null) {
                $idp = new Idp();
                if ($idp->getFromDB((int) $hint['idps_id']) && $idp->fields['protocol'] === Idp::PROTO_SAML) {
                    return $idp;
                }
            }
        }

        $saml = array_values(array_filter(Idp::getActive(), fn($row) => $row['protocol'] === Idp::PROTO_SAML));
        if (count($saml) === 1) {
            $idp = new Idp();
            if ($idp->getFromDB((int) $saml[0]['id'])) {
                return $idp;
            }
        }
        return null;
    }

    private static function resolveEmail(Idp $idp, string $subject, array $claims): string
    {
        $mapping = $idp->getClaimMapping();
        $claim   = (string) ($mapping['_useremails'] ?? 'mail');
        $value   = $claims[$claim] ?? '';
        if (is_array($value)) {
            $value = $value[0] ?? '';
        }
        $email = trim((string) $value);

        // NameID formato emailAddress: usable como email si no vino atributo.
        if ($email === '' && str_contains((string) $idp->fields['nameid_format'], 'emailAddress')) {
            $email = $subject;
        }
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : '';
    }

    /** Metadata XML del SP para registrar en el IdP. */
    public function metadata(): string
    {
        self::loadVendor();
        $settings = new OneLoginSettings($this->buildSettings(), true);
        $xml      = $settings->getSPMetadata();
        $errors   = $settings->validateMetadata($xml);
        if ($errors !== []) {
            throw new RuntimeException('invalid SP metadata: ' . implode(', ', $errors));
        }
        return $xml;
    }

    /**
     * Import de metadata del IdP (XML pegado o URL) → campos para la fila.
     *
     * @return array{idp_entity_id: string, idp_sso_url: string, idp_slo_url: string, idp_x509cert: string}
     */
    public static function parseIdpMetadata(string $xml): array
    {
        self::loadVendor();
        $xml = trim($xml);
        $parsed = str_starts_with($xml, 'http')
            ? IdPMetadataParser::parseRemoteXML($xml)
            : IdPMetadataParser::parseXML($xml);
        $idp    = $parsed['idp'] ?? [];
        return [
            'idp_entity_id' => (string) ($idp['entityId'] ?? ''),
            'idp_sso_url'   => (string) ($idp['singleSignOnService']['url'] ?? ''),
            'idp_slo_url'   => (string) ($idp['singleLogoutService']['url'] ?? ''),
            'idp_x509cert'  => (string) ($idp['x509cert'] ?? ($idp['x509certMulti']['signing'][0] ?? '')),
        ];
    }
}

<?php

/**
 * Suite de tests PHP puros del plugin SSO. Sin frameworks: corre con
 * `php tests/php/run.php` y sale con código != 0 si algo falla.
 *
 * Cubre los núcleos de seguridad extraídos como estáticos puros:
 *  - OidcClient::decodeWithKeys  (whitelist de alg, firma, exp/iat)
 *  - OidcClient::validateClaims  (iss, aud, azp, nonce)
 *  - LoginPipeline::resolveRedirect (anti open-redirect)
 *  - Identity (normalización de claims)
 * Es la versión unit de la matrix de ataques de M5: los rechazos que allá
 * se probaron contra Keycloak real acá quedan como regresión permanente.
 */

declare(strict_types=1);

define('GLPI_ROOT', __DIR__); // satisface el guard de los src, no se usa

require __DIR__ . '/../../vendor/autoload.php';
require __DIR__ . '/../../src/Identity.php';
require __DIR__ . '/../../src/OidcClient.php';
require __DIR__ . '/../../src/LoginPipeline.php';
require __DIR__ . '/../../src/ScimError.php';
require __DIR__ . '/../../src/ScimParser.php';
require __DIR__ . '/../../src/SamlClient.php';
require __DIR__ . '/../../src/Doctor.php';

use Firebase\JWT\JWT;
use GlpiPlugin\Sso\Doctor;
use GlpiPlugin\Sso\Identity;
use GlpiPlugin\Sso\LoginPipeline;
use GlpiPlugin\Sso\OidcClient;
use GlpiPlugin\Sso\ScimError;
use GlpiPlugin\Sso\ScimParser;
use GlpiPlugin\Sso\SamlClient;

$failures = 0;
$total    = 0;

function check(string $name, callable $fn): void
{
    global $failures, $total;
    $total++;
    try {
        $fn();
        echo "PASS  $name\n";
    } catch (\Throwable $e) {
        $failures++;
        echo "FAIL  $name\n      " . get_class($e) . ': ' . $e->getMessage() . "\n";
    }
}

/** Falla si el callable NO tira una excepción cuyo mensaje contenga $needle. */
function expectReject(callable $fn, string $needle = ''): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($needle !== '' && !str_contains($e->getMessage(), $needle) && !str_contains(get_class($e), $needle)) {
            throw new AssertionError(
                "rechazó, pero con otro motivo: [" . get_class($e) . '] ' . $e->getMessage()
                . " (esperaba «{$needle}»)"
            );
        }
        return;
    }
    throw new AssertionError('NO rechazó (esperaba excepción ' . ($needle !== '' ? "«{$needle}»" : '') . ')');
}

function assertSame(mixed $expected, mixed $actual, string $what = 'valor'): void
{
    if ($expected !== $actual) {
        throw new AssertionError(
            "$what: esperaba " . var_export($expected, true) . ', vino ' . var_export($actual, true)
        );
    }
}

function b64url(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

// ---------------------------------------------------------------- fixtures

$rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($rsa === false) {
    fwrite(STDERR, "No se pudo generar la clave RSA de prueba\n");
    exit(2);
}
$det  = openssl_pkey_get_details($rsa);
$jwks = ['keys' => [[
    'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'k1',
    'n' => b64url($det['rsa']['n']), 'e' => b64url($det['rsa']['e']),
]]];

$otherRsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

const ISSUER    = 'https://idp.example.test/realms/demo';
const CLIENT_ID = 'glpi-client';
const NONCE     = 'nonce-0123456789abcdef';

function claims(array $overrides = []): array
{
    return array_merge([
        'iss'   => ISSUER,
        'aud'   => CLIENT_ID,
        'sub'   => 'user-1',
        'iat'   => time(),
        'exp'   => time() + 300,
        'nonce' => NONCE,
    ], $overrides);
}

$conf = ['issuer' => ISSUER];

$sign = static fn (array $claims, $key = null, string $kid = 'k1'): string
    => JWT::encode($claims, $key ?? $GLOBALS['rsa'], 'RS256', $kid);

// ------------------------------------------- OidcClient::decodeWithKeys

check('JWT válido RS256 decodifica y conserva claims', function () use ($sign, $jwks) {
    $payload = OidcClient::decodeWithKeys($sign(claims()), $jwks);
    assertSame('user-1', (string) $payload->sub, 'sub');
});

check('alg=none forjado se rechaza por whitelist', function () use ($jwks) {
    $header  = b64url(json_encode(['typ' => 'JWT', 'alg' => 'none']));
    $payload = b64url(json_encode(claims()));
    expectReject(fn () => OidcClient::decodeWithKeys("$header.$payload.", $jwks), 'disallowed');
});

check('alg=HS256 se rechaza por whitelist (antes de verificar firma)', function () use ($jwks) {
    $jwt = JWT::encode(claims(), 'shared-secret', 'HS256');
    expectReject(fn () => OidcClient::decodeWithKeys($jwt, $jwks), 'disallowed');
});

check('payload tamperado rompe la firma', function () use ($sign, $jwks) {
    $parts    = explode('.', $sign(claims()));
    $tampered = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    $tampered['sub'] = 'admin';
    $parts[1] = b64url(json_encode($tampered));
    expectReject(fn () => OidcClient::decodeWithKeys(implode('.', $parts), $jwks), 'Signature');
});

check('token firmado con una clave ajena al JWKS se rechaza', function () use ($sign, $jwks, $otherRsa) {
    $jwt = $sign(claims(), $otherRsa);
    expectReject(fn () => OidcClient::decodeWithKeys($jwt, $jwks));
});

check('token expirado (más allá del skew) se rechaza', function () use ($sign, $jwks) {
    $jwt = $sign(claims(['iat' => time() - 7200, 'exp' => time() - 3600]));
    expectReject(fn () => OidcClient::decodeWithKeys($jwt, $jwks), 'Expired');
});

check('token emitido en el futuro (más allá del skew) se rechaza', function () use ($sign, $jwks) {
    $jwt = $sign(claims(['iat' => time() + 3600, 'nbf' => time() + 3600, 'exp' => time() + 7200]));
    expectReject(fn () => OidcClient::decodeWithKeys($jwt, $jwks));
});

check('JWT malformado (2 partes) se rechaza', function () use ($jwks) {
    expectReject(fn () => OidcClient::decodeWithKeys('abc.def', $jwks), 'malformed');
});

// ------------------------------------------- OidcClient::validateClaims

$decode = static function (array $overrides) use ($sign, $jwks): \stdClass {
    return OidcClient::decodeWithKeys($sign(claims($overrides)), $jwks);
};

check('claims válidos pasan', function () use ($decode, $conf) {
    $p = OidcClient::validateClaims($decode([]), $conf, CLIENT_ID, NONCE);
    assertSame('user-1', (string) $p->sub, 'sub');
});

check('issuer distinto se rechaza', function () use ($decode, $conf) {
    $p = $decode(['iss' => 'https://evil.example.test']);
    expectReject(fn () => OidcClient::validateClaims($p, $conf, CLIENT_ID, NONCE), 'issuer');
});

check('audience ajena se rechaza', function () use ($decode, $conf) {
    $p = $decode(['aud' => 'otro-cliente']);
    expectReject(fn () => OidcClient::validateClaims($p, $conf, CLIENT_ID, NONCE), 'audience');
});

check('multi-audience sin azp se rechaza', function () use ($decode, $conf) {
    $p = $decode(['aud' => [CLIENT_ID, 'otro-cliente']]);
    expectReject(fn () => OidcClient::validateClaims($p, $conf, CLIENT_ID, NONCE), 'azp');
});

check('multi-audience con azp correcto pasa', function () use ($decode, $conf) {
    $p = OidcClient::validateClaims(
        $decode(['aud' => [CLIENT_ID, 'otro-cliente'], 'azp' => CLIENT_ID]),
        $conf,
        CLIENT_ID,
        NONCE
    );
    assertSame('user-1', (string) $p->sub, 'sub');
});

check('nonce distinto se rechaza', function () use ($decode, $conf) {
    $p = $decode(['nonce' => 'otro-nonce']);
    expectReject(fn () => OidcClient::validateClaims($p, $conf, CLIENT_ID, NONCE), 'nonce');
});

check('nonce esperado vacío se rechaza (fail-closed)', function () use ($decode, $conf) {
    $p = $decode(['nonce' => '']);
    expectReject(fn () => OidcClient::validateClaims($p, $conf, CLIENT_ID, ''), 'nonce');
});

// -------------------------------------- LoginPipeline::resolveRedirect

const BASE = 'https://glpi.example.test';

check('redirect vacío cae a la base', function () {
    assertSame(BASE . '/', LoginPipeline::resolveRedirect('', BASE));
});

check('destino interno se respeta', function () {
    $url = BASE . '/front/ticket.form.php?id=42';
    assertSame($url, LoginPipeline::resolveRedirect($url, BASE));
});

check('host externo cae a la base', function () {
    assertSame(BASE . '/', LoginPipeline::resolveRedirect('https://evil.test/x', BASE));
});

check('prefijo confuso (base.evil.test) cae a la base', function () {
    assertSame(BASE . '/', LoginPipeline::resolveRedirect(BASE . '.evil.test/x', BASE));
});

check('protocol-relative //evil cae a la base', function () {
    assertSame(BASE . '/', LoginPipeline::resolveRedirect('//evil.test/x', BASE));
});

check('base misma sin slash final cae a la base (no es prefijo interno)', function () {
    assertSame(BASE . '/', LoginPipeline::resolveRedirect(BASE, BASE));
});

check('sin base configurada devuelve raíz', function () {
    assertSame('/', LoginPipeline::resolveRedirect('https://x/y', ''));
});

// ----------------------------------------------------------- Identity

check('claim escalar, array y ausente', function () {
    $i = new Identity('s', ['a' => ' v ', 'b' => ['x', 'y'], 'c' => 42]);
    assertSame('v', $i->claim('a'));
    assertSame('x', $i->claim('b'));
    assertSame('42', $i->claim('c'));
    assertSame('', $i->claim('nope'));
});

check('claimList normaliza escalares, vacíos y no-strings', function () {
    $i = new Identity('s', ['g' => ['dev', '', 'ops', 7], 'one' => 'solo', 'empty' => '']);
    assertSame(['dev', 'ops', '7'], $i->claimList('g'));
    assertSame(['solo'], $i->claimList('one'));
    assertSame([], $i->claimList('empty'));
    assertSame([], $i->claimList('nope'));
});

check('emailDomain minúsculas y último @', function () {
    assertSame('example.test', (new Identity('s', [], 'User@EXAMPLE.TEST'))->emailDomain());
    assertSame('b.test', (new Identity('s', [], 'weird@a@B.TEST'))->emailDomain());
    assertSame('', (new Identity('s'))->emailDomain());
});

check('toArray/fromArray es ida y vuelta completa', function () {
    $i = new Identity('subj', ['g' => ['x']], 'a@b.c', true);
    $j = Identity::fromArray($i->toArray());
    assertSame($i->subject, $j->subject);
    assertSame($i->claims, $j->claims);
    assertSame($i->email, $j->email);
    assertSame($i->email_verified, $j->email_verified);
    assertSame(null, Identity::fromArray(['subject' => 's'])->email_verified, 'email_verified ausente');
});

// -------------------------------------------------------- ScimParser

check('filtro eq válido, atributo case-insensitive y escape JSON', function () {
    assertSame(['userName', 'ana'], ScimParser::parseEqFilter('userName eq "ana"', ['userName']));
    assertSame(['userName', 'ana'], ScimParser::parseEqFilter('USERNAME eq "ana"', ['userName']));
    assertSame(['userName', 'a"b'], ScimParser::parseEqFilter('userName eq "a\\"b"', ['userName']));
});

check('filtros no soportados se rechazan con invalidFilter', function () {
    expectReject(fn () => ScimParser::parseEqFilter('userName sw "a"', ['userName']), 'filters');
    expectReject(fn () => ScimParser::parseEqFilter('userName eq "a" and active eq "true"', ['userName']), 'filters');
    expectReject(fn () => ScimParser::parseEqFilter('otro eq "a"', ['userName']), 'attribute');
});

check('boolValue acepta variantes reales y jamás trata "False" como truthy', function () {
    assertSame(true, ScimParser::boolValue(true));
    assertSame(false, ScimParser::boolValue(false));
    assertSame(true, ScimParser::boolValue(1));
    assertSame(false, ScimParser::boolValue(0));
    assertSame(true, ScimParser::boolValue('True'));
    assertSame(false, ScimParser::boolValue('False'));
    assertSame(false, ScimParser::boolValue(' false '));
    expectReject(fn () => ScimParser::boolValue('yes'), 'boolean');
});

function patchBody(array $ops): array
{
    return ['schemas' => [ScimParser::PATCH_SCHEMA], 'Operations' => $ops];
}

check('PATCH de user: paths soportados, remove y path vacío', function () {
    $changes = ScimParser::parseUserPatch(patchBody([
        ['op' => 'Replace', 'path' => 'userName', 'value' => 'nuevo'],
        ['op' => 'replace', 'path' => 'active', 'value' => 'False'],
        ['op' => 'add', 'path' => 'name.givenName', 'value' => 'Ana'],
        ['op' => 'remove', 'path' => 'emails'],
        ['op' => 'replace', 'path' => '', 'value' => ['name' => ['familyName' => 'Prueba']]],
    ]));
    assertSame('nuevo', $changes['userName']);
    assertSame(false, $changes['active']);
    assertSame('Ana', $changes['name']['givenName']);
    assertSame([], $changes['emails']);
    assertSame('Prueba', $changes['name']['familyName']);
});

check('PATCH de user: schema faltante, op inválida y path desconocido', function () {
    expectReject(fn () => ScimParser::parseUserPatch(['Operations' => []]), 'schema');
    expectReject(fn () => ScimParser::parseUserPatch(patchBody([['op' => 'move', 'path' => 'userName', 'value' => 'x']])), 'operation');
    expectReject(fn () => ScimParser::parseUserPatch(patchBody([['op' => 'replace', 'path' => 'title', 'value' => 'x']])), 'path');
});

check('PATCH de group: display, members y remove puntual, en orden', function () {
    $ops = ScimParser::parseGroupPatch(patchBody([
        ['op' => 'replace', 'path' => 'displayName', 'value' => 'Equipo'],
        ['op' => 'add', 'path' => 'members', 'value' => [['value' => '7']]],
        ['op' => 'remove', 'path' => 'members[value eq "9"]'],
        ['op' => 'replace', 'path' => '', 'value' => ['members' => [['value' => '5']]]],
    ]));
    assertSame('display', $ops[0]['kind']);
    assertSame('Equipo', $ops[0]['value']);
    assertSame(['kind' => 'members', 'op' => 'add', 'members' => [['value' => '7']]], $ops[1]);
    assertSame(['kind' => 'remove_member', 'users_id' => 9], $ops[2]);
    assertSame('replace', $ops[3]['op']);
});

check('PATCH de group: displayName no se puede remover (mutability)', function () {
    expectReject(
        fn () => ScimParser::parseGroupPatch(patchBody([['op' => 'remove', 'path' => 'displayName']])),
        'removed'
    );
});

// ----------------------------------------- SamlClient::settingsFromFields

function samlFields(array $overrides = []): array
{
    return array_merge([
        'id' => 2, 'idp_entity_id' => 'https://idp.example.test/realms/demo',
        'idp_sso_url' => 'https://idp.example.test/sso', 'idp_slo_url' => 'https://idp.example.test/slo',
        'idp_x509cert' => 'CERT-A', 'idp_x509cert_rollover' => '',
        'sp_x509cert' => '', 'nameid_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'sign_authn_requests' => 0, 'want_assertions_encrypted' => 0,
    ], $overrides);
}

check('settings SAML: política de seguridad no negociable', function () {
    $s = SamlClient::settingsFromFields(samlFields(), 'https://glpi.example.test/plugins/sso', '');
    assertSame(true, $s['strict'], 'strict');
    assertSame(true, $s['security']['wantAssertionsSigned'], 'wantAssertionsSigned');
    assertSame(true, $s['security']['wantNameId'], 'wantNameId');
    assertSame(false, $s['security']['relaxDestinationValidation'], 'relaxDestination');
    assertSame('https://glpi.example.test/plugins/sso/front/metadata.php?idp=2', $s['sp']['entityId'], 'entityId');
    assertSame('https://glpi.example.test/plugins/sso/front/acs.php', $s['sp']['assertionConsumerService']['url'], 'acs');
    assertSame('CERT-A', $s['idp']['x509cert'], 'cert simple');
});

check('settings SAML: rollover de certificado arma x509certMulti', function () {
    $s = SamlClient::settingsFromFields(
        samlFields(['idp_x509cert_rollover' => 'CERT-B']),
        'https://glpi.example.test/plugins/sso',
        ''
    );
    assertSame(['CERT-A', 'CERT-B'], $s['idp']['x509certMulti']['signing'], 'signing');
    assertSame(['CERT-A'], $s['idp']['x509certMulti']['encryption'], 'encryption');
    assertSame(false, isset($s['idp']['x509cert']), 'sin cert simple');
});

check('metadata de IdP se parsea a los campos de la fila', function () {
    $xml = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/realms/demo">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>QkFTRTY0Q0VSVA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/slo"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
    $f = SamlClient::parseIdpMetadata($xml);
    assertSame('https://idp.example.test/realms/demo', $f['idp_entity_id']);
    assertSame('https://idp.example.test/sso', $f['idp_sso_url']);
    assertSame('https://idp.example.test/slo', $f['idp_slo_url']);
    assertSame('QkFTRTY0Q0VSVA==', $f['idp_x509cert']);
});

// ------------------------------------------------- Doctor::isPrivateHost

check('isPrivateHost: RFC1918, loopback y localhost', function () {
    assertSame(true, Doctor::isPrivateHost('http://10.0.0.5:8081/realms/x'));
    assertSame(true, Doctor::isPrivateHost('http://172.20.1.9/x'));
    assertSame(true, Doctor::isPrivateHost('http://192.168.0.10/x'));
    assertSame(true, Doctor::isPrivateHost('http://127.0.0.1/x'));
    assertSame(true, Doctor::isPrivateHost('http://localhost:8081/x'));
});

check('isPrivateHost: públicos exigen HTTPS', function () {
    assertSame(false, Doctor::isPrivateHost('http://8.8.8.8/x'));
    assertSame(false, Doctor::isPrivateHost('http://100.64.0.1/x'));
    assertSame(false, Doctor::isPrivateHost('http://idp.example.com/x'));
    assertSame(false, Doctor::isPrivateHost(''));
});

// -------------------------------------------------------------- resumen

echo "\n" . ($total - $failures) . "/$total tests en verde\n";
exit($failures === 0 ? 0 : 1);

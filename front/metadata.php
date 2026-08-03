<?php
/**
 * Metadata XML del SP: /plugins/sso/front/metadata.php?idp=N
 * Público (se necesita para registrar GLPI en el IdP, incluso antes de
 * activar el IdP acá). Sólo requiere que el IdP exista y sea SAML.
 */

use GlpiPlugin\Sso\Idp;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

// Sólo GET/HEAD: es un documento de descubrimiento, no acepta mutaciones.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

$idps_id = (int) ($_GET['idp'] ?? 0);

$idp = new Idp();
if (!$idps_id || !$idp->getFromDB($idps_id) || $idp->fields['protocol'] !== Idp::PROTO_SAML) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'unknown SAML identity provider';
    exit;
}

try {
    $xml = (new SamlClient($idp))->metadata();
    header('Content-Type: application/samlmetadata+xml; charset=utf-8');
    header('Content-Disposition: inline; filename="sso-sp-metadata-' . $idps_id . '.xml"');
    echo $xml;
} catch (\Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'metadata error: ' . $e->getMessage();
}

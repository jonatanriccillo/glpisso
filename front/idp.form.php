<?php
/**
 * CRUD de un proveedor de identidad.
 */

use GlpiPlugin\Sso\Idp;
use GlpiPlugin\Sso\SamlClient;

include('../../../inc/includes.php');

Session::checkRight('plugin_sso', READ);

$idp = new Idp();

if (isset($_POST['import_metadata'])) {
    $idp->check((int) $_POST['id'], UPDATE, $_POST);
    try {
        $parsed = SamlClient::parseIdpMetadata((string) ($_POST['metadata_xml'] ?? ''));
        $parsed = array_filter($parsed, fn($v) => trim((string) $v) !== '');
        if ($parsed === []) {
            throw new RuntimeException(__('no usable IdP data found', 'sso'));
        }
        $idp->update(['id' => (int) $_POST['id']] + $parsed);
        Session::addMessageAfterRedirect(__('IdP metadata imported', 'sso'), false, INFO);
    } catch (\Throwable $e) {
        Session::addMessageAfterRedirect(
            sprintf(__('Metadata import failed: %s', 'sso'), $e->getMessage()),
            false,
            ERROR
        );
    }
    Html::back();
} elseif (isset($_POST['generate_scim_token'])) {
    $idp->check((int) $_POST['id'], UPDATE, $_POST);
    $token = $idp->generateScimToken();
    Session::addMessageAfterRedirect(
        sprintf(__('SCIM token (copy it now; it will not be shown again): %s', 'sso'), $token),
        false,
        WARNING
    );
    Html::back();
} elseif (isset($_POST['revoke_scim_token'])) {
    $idp->check((int) $_POST['id'], UPDATE, $_POST);
    $idp->revokeScimToken();
    Session::addMessageAfterRedirect(__('SCIM token revoked', 'sso'), false, INFO);
    Html::back();
} elseif (isset($_POST['add'])) {
    $idp->check(-1, CREATE, $_POST);
    if ($newID = $idp->add($_POST)) {
        Html::redirect(Idp::getFormURLWithID($newID));
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    $idp->check((int) $_POST['id'], UPDATE, $_POST);
    $idp->update($_POST);
    Html::back();
} elseif (isset($_POST['delete'])) {
    $idp->check((int) $_POST['id'], DELETE, $_POST);
    $idp->delete($_POST);
    $idp->redirectToList();
} elseif (isset($_POST['restore'])) {
    $idp->check((int) $_POST['id'], DELETE, $_POST);
    $idp->restore($_POST);
    $idp->redirectToList();
} elseif (isset($_POST['purge'])) {
    $idp->check((int) $_POST['id'], PURGE, $_POST);
    $idp->delete($_POST, true);
    $idp->redirectToList();
} else {
    Html::header(
        Idp::getTypeName(2),
        $_SERVER['PHP_SELF'],
        'config',
        'GlpiPlugin\Sso\Menu'
    );
    $idp->display(['id' => (int) ($_GET['id'] ?? 0)]);
    Html::footer();
}

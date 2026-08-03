<?php

namespace GlpiPlugin\Sso;

use Auth as GlpiAuth;
use Profile_User;
use Session;
use User;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Orquestador post-autenticación, común a SAML y OIDC. Único punto donde se
 * crea la sesión GLPI. Fail-closed: cualquier condición no satisfecha termina
 * en deny() con log y página neutra (el detalle queda en _logs, nunca en el
 * navegador).
 *
 * El protocolo entrega la Identity en el endpoint stateless (acs/callback),
 * que emite un ticket one-shot y redirige a finish.php (GET con sesión), que
 * llama completeFromTicket(). Así ni el CSRF del POST cross-site ni SameSite
 * tocan el camino de la sesión.
 */
class LoginPipeline
{
    /** Emite el ticket one-shot y devuelve la URL de finalización. */
    public static function issueTicket(Idp $idp, Identity $identity, string $redirect, array $session = []): string
    {
        $token = RequestState::newToken();
        $ok = RequestState::stash(
            RequestState::KIND_LOGIN_TICKET,
            $token,
            (int) $idp->getID(),
            ['identity' => $identity->toArray(), 'redirect' => $redirect, 'session' => $session],
            RequestState::TICKET_TTL
        );
        if (!$ok) {
            throw new \RuntimeException('could not persist login ticket');
        }
        return Config::baseUrl() . '/plugins/sso/front/finish.php?t=' . $token;
    }

    /** Punto de entrada de finish.php. No retorna. */
    public static function completeFromTicket(string $token): void
    {
        $data = RequestState::consume(RequestState::KIND_LOGIN_TICKET, $token);
        if ($data === null) {
            Log::record('login_denied', Log::LEVEL_WARNING, 'invalid or expired login ticket');
            self::failPage(__('Invalid or expired login ticket', 'sso'));
        }

        $idp = new Idp();
        if (
            !$idp->getFromDB((int) $data['idps_id'])
            || !(bool) $idp->fields['is_active']
            || (bool) $idp->fields['is_deleted']
        ) {
            Log::record('login_denied', Log::LEVEL_WARNING, 'idp unavailable at finish', ['idps_id' => (int) $data['idps_id']]);
            self::failPage(__('Unknown or inactive identity provider', 'sso'));
        }

        $identity = Identity::fromArray(is_array($data['identity'] ?? null) ? $data['identity'] : []);
        if ($identity->subject === '') {
            Log::record('login_denied', Log::LEVEL_ERROR, 'ticket without subject', ['idps_id' => (int) $idp->getID()]);
            self::failPage(__('Authentication failed', 'sso'));
        }

        // Reglas ANTES de resolver/crear: un deny no debe dejar usuarios
        // huérfanos creados por JIT. Las asignaciones se aplican después.
        $rules = self::evaluateRules($idp, $identity);
        [$users_id, $created] = self::resolveUser($idp, $identity);
        if ($rules !== null && ($idp->fields['rules_mode'] !== 'on_create_only' || $created)) {
            self::applyRuleOutput($idp, $users_id, $rules);
        }
        self::establishSession(
            $idp,
            $identity,
            $users_id,
            (string) ($data['redirect'] ?? ''),
            is_array($data['session'] ?? null) ? $data['session'] : []
        );
    }

    // ------------------------------------------------------------------
    // Resolución de usuario: link estable → matching/adopción → JIT
    // ------------------------------------------------------------------

    /** @return array{0: int, 1: bool} [users_id, fue creado en este login] */
    private static function resolveUser(Idp $idp, Identity $identity): array
    {
        $idps_id = (int) $idp->getID();

        // 1. Link estable por subject (sobrevive cambios de email).
        $users_id = UserLink::lookup($idps_id, $identity->subject);
        if ($users_id !== null) {
            if ((bool) $idp->fields['jit_update']) {
                self::syncUserFields($idp, $identity, $users_id);
            }
            return [$users_id, false];
        }

        // 2. Allowlist de dominios (si está configurada).
        if (!self::domainAllowed($idp, $identity)) {
            self::deny($idp, $identity, 'email domain not allowed: ' . $identity->emailDomain(),
                __('Your account is not allowed to log in', 'sso'));
        }

        // 3. Matching de usuario preexistente (primera vinculación).
        $users_id = self::matchExisting($idp, $identity);
        if ($users_id !== null) {
            if (!(bool) Config::value('adopt_existing')) {
                self::deny($idp, $identity, 'matching user exists but adoption is disabled (users_id ' . $users_id . ')',
                    __('Your account is not allowed to log in', 'sso'));
            }
            // Adopción: link + authtype a EXTERNAL.
            $user = new User();
            $user->update(['id' => $users_id, 'authtype' => GlpiAuth::EXTERNAL, 'auths_id' => 0]);
            UserLink::link($idps_id, $identity->subject, $users_id);
            Log::record('user_adopted', Log::LEVEL_INFO, 'existing user adopted via ' . $idp->fields['matching_field'],
                ['idps_id' => $idps_id, 'users_id' => $users_id]);
            if ((bool) $idp->fields['jit_update']) {
                self::syncUserFields($idp, $identity, $users_id);
            }
            return [$users_id, false];
        }

        // 4. JIT: sólo si está habilitado explícitamente (default OFF).
        if (!(bool) $idp->fields['jit_create']) {
            self::deny($idp, $identity, 'unknown user and JIT creation is disabled (subject ' . $identity->subject . ')',
                __('Your account is not allowed to log in', 'sso'));
        }
        return [self::jitCreate($idp, $identity), true];
    }

    private static function domainAllowed(Idp $idp, Identity $identity): bool
    {
        $allowlist = trim((string) $idp->fields['domain_allowlist']);
        if ($allowlist === '') {
            return true;
        }
        $domains = array_filter(array_map(fn($d) => strtolower(trim($d)), explode(',', $allowlist)));
        return in_array($identity->emailDomain(), $domains, true);
    }

    /** @return int|null users_id preexistente que matchea, null si no hay */
    private static function matchExisting(Idp $idp, Identity $identity): ?int
    {
        global $DB;

        if ($idp->fields['matching_field'] === 'email') {
            if ($identity->email === '') {
                return null;
            }
            // OIDC exige email verificado para matchear (decisión §2).
            if (
                $idp->fields['protocol'] === Idp::PROTO_OIDC
                && (bool) $idp->fields['require_email_verified']
                && $identity->email_verified !== true
            ) {
                self::deny($idp, $identity, 'email not verified by the IdP: ' . $identity->email,
                    __('Your account is not allowed to log in', 'sso'));
            }

            $found = [];
            foreach ($DB->request([
                'SELECT'   => ['glpi_useremails.users_id'],
                'DISTINCT' => true,
                'FROM'     => 'glpi_useremails',
                'INNER JOIN' => ['glpi_users' => ['ON' => ['glpi_useremails' => 'users_id', 'glpi_users' => 'id']]],
                'WHERE'    => ['glpi_useremails.email' => $identity->email, 'glpi_users.is_deleted' => 0],
            ]) as $row) {
                $found[] = (int) $row['users_id'];
            }
            if (count($found) > 1) {
                self::deny($idp, $identity, 'ambiguous email match (' . count($found) . ' users): ' . $identity->email,
                    __('Your account is not allowed to log in', 'sso'));
            }
            return $found[0] ?? null;
        }

        // matching por login
        $login = self::loginFor($idp, $identity);
        if ($login === '') {
            return null;
        }
        $user = new User();
        if ($user->getFromDBbyName($login) && !(bool) $user->fields['is_deleted']) {
            return (int) $user->getID();
        }
        return null;
    }

    /** Login candidato: claim mapeado a `name`, fallback email. */
    private static function loginFor(Idp $idp, Identity $identity): string
    {
        $mapping = $idp->getClaimMapping();
        $login = $identity->claim((string) ($mapping['name'] ?? ''));
        if ($login === '') {
            $login = $identity->email;
        }
        return $login;
    }

    private static function jitCreate(Idp $idp, Identity $identity): int
    {
        $login = self::loginFor($idp, $identity);
        if ($login === '') {
            self::deny($idp, $identity, 'JIT: no usable login (no name claim, no email)',
                __('Authentication failed', 'sso'));
        }

        // Colisión: existe un usuario con ese login que el matching NO eligió
        // (p. ej. matching por email y el email no coincide). No se secuestra.
        $existing = new User();
        if ($existing->getFromDBbyName($login)) {
            self::deny($idp, $identity, 'JIT: login collision with existing user: ' . $login,
                __('Your account is not allowed to log in', 'sso'));
        }

        $mapping = $idp->getClaimMapping();
        $input = [
            'name'        => $login,
            'realname'    => $identity->claim((string) ($mapping['realname'] ?? '')),
            'firstname'   => $identity->claim((string) ($mapping['firstname'] ?? '')),
            'phone'       => $identity->claim((string) ($mapping['phone'] ?? '')),
            'authtype'    => GlpiAuth::EXTERNAL,
            'auths_id'    => 0,
            'is_active'   => 1,
            'entities_id' => (int) $idp->fields['default_entities_id'],
        ];
        if ($identity->email !== '') {
            $input['_useremails'] = [-1 => $identity->email];
        }

        $user = new User();
        $users_id = $user->add($input);
        if (!$users_id) {
            self::deny($idp, $identity, 'JIT: user creation failed for ' . $login,
                __('Authentication failed', 'sso'));
        }

        // Habilitación default (nunca admin — se valida en la config, acá se aplica).
        if ((int) $idp->fields['default_profiles_id'] > 0) {
            (new Profile_User())->add([
                'users_id'     => $users_id,
                'profiles_id'  => (int) $idp->fields['default_profiles_id'],
                'entities_id'  => (int) $idp->fields['default_entities_id'],
                'is_recursive' => 0,
                'is_dynamic'   => 0,
            ]);
        }

        UserLink::link((int) $idp->getID(), $identity->subject, (int) $users_id);
        Log::record('jit_created', Log::LEVEL_INFO, 'user created via JIT: ' . $login,
            ['idps_id' => (int) $idp->getID(), 'users_id' => (int) $users_id]);
        return (int) $users_id;
    }

    /** Sync de campos mapeados en cada login (jit_update). Nunca toca `name`. */
    private static function syncUserFields(Idp $idp, Identity $identity, int $users_id): void
    {
        $mapping = $idp->getClaimMapping();
        $user = new User();
        if (!$user->getFromDB($users_id)) {
            return;
        }

        $update = ['id' => $users_id];
        foreach (['realname', 'firstname', 'phone'] as $field) {
            $value = $identity->claim((string) ($mapping[$field] ?? ''));
            if ($value !== '' && $value !== (string) $user->fields[$field]) {
                $update[$field] = $value;
            }
        }
        if (count($update) > 1) {
            $user->update($update);
            Log::debug('jit_updated', 'synced fields: ' . implode(', ', array_keys(array_slice($update, 1))),
                ['idps_id' => (int) $idp->getID(), 'users_id' => $users_id]);
        }

        // Email nuevo del IdP → se agrega (no se borran los existentes).
        if ($identity->email !== '') {
            $has = countElementsInTable('glpi_useremails', ['users_id' => $users_id, 'email' => $identity->email]);
            if ($has === 0) {
                (new \UserEmail())->add(['users_id' => $users_id, 'email' => $identity->email]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Reglas de autorización (engine nativo, ver RuleAuth)
    // ------------------------------------------------------------------

    /**
     * Evalúa las reglas y corta acá mismo si hay deny o fail-closed (antes
     * de que exista/se cree el usuario). Devuelve el output para aplicar, o
     * null si ninguna regla matcheó (quedan los defaults del IdP).
     */
    private static function evaluateRules(Idp $idp, Identity $identity): ?array
    {
        $input  = self::ruleInput($idp, $identity);
        $output = (new RuleAuthCollection())->processAllRules($input, [], []);

        $matched = array_values(array_unique((array) ($output['_sso_matched'] ?? [])));

        if (($output['_sso_deny'] ?? false) === true) {
            self::deny($idp, $identity, 'denied by rule: ' . implode(', ', $matched),
                __('Your account is not allowed to log in', 'sso'));
        }

        if ($matched === []) {
            if ((int) Config::value('fail_closed') === 1) {
                self::deny($idp, $identity, 'no authorization rule matched (fail closed)',
                    __('Your account is not allowed to log in', 'sso'));
            }
            return null; // sin match: quedan los defaults del IdP
        }

        $output['_sso_matched'] = $matched;
        return $output;
    }

    /** Aplica el output de las reglas sobre el usuario ya resuelto. */
    private static function applyRuleOutput(Idp $idp, int $users_id, array $output): void
    {
        $matched = (array) ($output['_sso_matched'] ?? []);

        // Grants: completar entidad/perfil faltante con los defaults del IdP.
        $grants = [];
        foreach ((array) ($output['_sso_grants'] ?? []) as $g) {
            $e = $g['entities_id'] !== null ? (int) $g['entities_id'] : (int) $idp->fields['default_entities_id'];
            $p = $g['profiles_id'] !== null ? (int) $g['profiles_id'] : (int) $idp->fields['default_profiles_id'];
            $r = (int) ($g['is_recursive'] ?? 0);
            if ($p > 0) {
                $grants[$e . '-' . $p . '-' . $r] = [
                    'entities_id'  => $e,
                    'profiles_id'  => $p,
                    'is_recursive' => $r,
                ];
            }
        }

        // Recalculo dinámico (mismo mecanismo que LDAP): lo que las reglas ya
        // no otorgan, se quita; lo manual (is_dynamic=0) no se toca.
        self::reconcileProfiles($users_id, $grants);
        self::reconcileGroups($users_id, array_values(array_unique(array_map('intval', (array) ($output['_sso_groups'] ?? [])))));

        $update = ['id' => $users_id];
        if (isset($output['_sso_is_active'])) {
            $update['is_active'] = (int) $output['_sso_is_active'];
        }
        if (isset($output['_sso_default_entity'])) {
            $update['entities_id'] = (int) $output['_sso_default_entity'];
        }
        if (isset($output['_sso_default_profile'])) {
            $update['profiles_id'] = (int) $output['_sso_default_profile'];
        }
        if (isset($output['_sso_timezone'])) {
            $update['timezone'] = (string) $output['_sso_timezone'];
        }
        if (isset($output['_sso_language'])) {
            $update['language'] = (string) $output['_sso_language'];
        }
        if (count($update) > 1) {
            (new User())->update($update);
        }

        Log::record('rule_matched', Log::LEVEL_INFO, implode(', ', $matched), [
            'idps_id'  => (int) $idp->getID(),
            'users_id' => $users_id,
            'grants'   => count($grants),
            'groups'   => count((array) ($output['_sso_groups'] ?? [])),
        ]);
    }

    /** Input plano para el engine: campos resueltos + claims crudos. */
    private static function ruleInput(Idp $idp, Identity $identity): array
    {
        $mapping = $idp->getClaimMapping();
        $groups_claim = trim((string) $idp->fields['groups_claim']) !== '' ? $idp->fields['groups_claim'] : 'groups';

        $input = [
            '_idps_id'      => (int) $idp->getID(),
            'protocol'      => (string) $idp->fields['protocol'],
            'login'         => self::loginFor($idp, $identity),
            'email'         => $identity->email,
            '_email_domain' => $identity->emailDomain(),
            '_groups'       => $identity->claimList((string) $groups_claim),
            'firstname'     => $identity->claim((string) ($mapping['firstname'] ?? '')),
            'realname'      => $identity->claim((string) ($mapping['realname'] ?? '')),
        ];

        foreach ($identity->claims as $key => $value) {
            $input['claim_' . $key] = is_array($value)
                ? array_values(array_map('strval', $value))
                : (string) $value;
        }

        return $input;
    }

    private static function reconcileProfiles(int $users_id, array $desired): void
    {
        global $DB;

        $existing = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_profiles_users',
            'WHERE' => ['users_id' => $users_id, 'is_dynamic' => 1],
        ]) as $row) {
            $existing[$row['entities_id'] . '-' . $row['profiles_id'] . '-' . $row['is_recursive']] = (int) $row['id'];
        }

        foreach ($desired as $key => $grant) {
            if (!isset($existing[$key])) {
                (new Profile_User())->add($grant + ['users_id' => $users_id, 'is_dynamic' => 1]);
            }
        }
        foreach ($existing as $key => $id) {
            if (!isset($desired[$key])) {
                (new Profile_User())->delete(['id' => $id], true);
            }
        }
    }

    private static function reconcileGroups(int $users_id, array $desired): void
    {
        global $DB;

        $existing = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_groups_users',
            'WHERE' => ['users_id' => $users_id, 'is_dynamic' => 1],
        ]) as $row) {
            $existing[(int) $row['groups_id']] = (int) $row['id'];
        }

        foreach ($desired as $groups_id) {
            if ($groups_id > 0 && !isset($existing[$groups_id])) {
                (new \Group_User())->add(['users_id' => $users_id, 'groups_id' => $groups_id, 'is_dynamic' => 1]);
            }
        }
        foreach ($existing as $groups_id => $id) {
            if (!in_array($groups_id, $desired, true)) {
                (new \Group_User())->delete(['id' => $id], true);
            }
        }
    }

    // ------------------------------------------------------------------
    // Sesión y salida
    // ------------------------------------------------------------------

    private static function establishSession(Idp $idp, Identity $identity, int $users_id, string $redirect, array $session_data = []): void
    {
        $user = new User();
        if (!$user->getFromDB($users_id) || !(bool) $user->fields['is_active'] || (bool) $user->fields['is_deleted']) {
            self::deny($idp, $identity, 'user inactive or deleted (users_id ' . $users_id . ')',
                __('Your account is not allowed to log in', 'sso'));
        }

        // Patrón verificado contra Auth::login de GLPI 11 (spike M0 #4).
        $auth = new GlpiAuth();
        $auth->auth_succeded = true;
        $auth->extauth       = 1;
        $auth->user_present  = true;
        $auth->user->getFromDB($users_id);
        $auth->user->fields['authtype']   = GlpiAuth::EXTERNAL;
        $auth->user->fields['last_login'] = date('Y-m-d H:i:s');
        $auth->user->fields['_extauth']   = 1;
        Session::init($auth);

        $_SESSION['plugin_sso_idps_id'] = (int) $idp->getID();

        // Hint one-shot para el Single Logout (M4): token en cookie httpOnly,
        // datos sensibles (id_token / session_index) sólo en DB.
        $hint_token = RequestState::newToken();
        $stashed = RequestState::stash(RequestState::KIND_LOGOUT_HINT, $hint_token, (int) $idp->getID(),
            ['protocol' => (string) $idp->fields['protocol']] + $session_data, RequestState::HINT_TTL);
        if ($stashed) {
            setcookie('sso_lt', $hint_token, [
                'expires'  => time() + RequestState::HINT_TTL,
                'path'     => '/',
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }

        Log::record('login_ok', Log::LEVEL_INFO, 'login via ' . $idp->fields['name'],
            ['idps_id' => (int) $idp->getID(), 'users_id' => $users_id]);

        self::landAfterLogin(self::safeRedirect($redirect));
    }

    private static function landAfterLogin(string $url): never
    {
        $safe = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8">'
            . '<meta http-equiv="refresh" content="0;url=' . $safe . '">'
            . '<title>GLPI</title></head><body>'
            . '<script>window.location.replace(' . json_encode($url) . ');</script>'
            . '<a href="' . $safe . '">' . htmlspecialchars(__('Continue', 'sso'), ENT_QUOTES, 'UTF-8') . '</a>'
            . '</body></html>';
        exit;
    }

    /** Anti open-redirect: sólo destinos dentro de la base URL del SSO. */
    private static function safeRedirect(string $redirect): string
    {
        // Base del plugin (no el url_base del core): la sesión/cookie vive en
        // el host por el que entró el flujo SSO. A la raíz: GLPI enruta según
        // la interfaz del perfil (central.php daría 403 a Self-Service).
        return self::resolveRedirect($redirect, Config::baseUrl());
    }

    /** Núcleo puro (unit-testeable) del anti open-redirect. */
    public static function resolveRedirect(string $redirect, string $base): string
    {
        $default = $base . '/';

        $redirect = trim($redirect);
        if ($redirect === '' || $base === '') {
            return $default;
        }
        if (str_starts_with($redirect, $base . '/')) {
            return $redirect;
        }
        return $default;
    }

    /** Log + página neutra. No retorna. */
    private static function deny(Idp $idp, Identity $identity, string $log_reason, string $user_message): never
    {
        Log::record('login_denied', Log::LEVEL_WARNING, $log_reason, [
            'idps_id' => (int) $idp->getID(),
            'subject' => $identity->subject,
            'email'   => $identity->email,
        ]);
        self::failPage($user_message);
    }

    /** Página de error mínima y neutra (sin detalle técnico). No retorna. */
    public static function failPage(string $message): never
    {
        global $CFG_GLPI;

        $login_url = rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/') . '/index.php?noAUTO=1';

        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SSO</title></head>'
            . '<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; margin-top: 10vh; background: #f6f7f9">'
            . '<div style="max-width: 460px; text-align: center; background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 2em">'
            . '<h2 style="margin-top: 0">' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</h2>'
            . '<p><a href="' . htmlspecialchars($login_url, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars(__('Back to login', 'sso'), ENT_QUOTES, 'UTF-8') . '</a></p>'
            . '</div></body></html>';
        exit;
    }
}

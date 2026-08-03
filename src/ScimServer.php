<?php

namespace GlpiPlugin\Sso;

use Auth as GlpiAuth;
use Group;
use Group_User;
use Profile_User;
use RuntimeException;
use User;
use UserEmail;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Servidor SCIM 2.0 mínimo-interoperable para lifecycle push.
 *
 * Recursos: Users, Groups y discovery. Cada Bearer resuelve un único IdP y
 * todas las consultas se acotan por sus links/mapeos; nunca existe acceso
 * cruzado entre tenants/IdPs. El token en claro no se persiste.
 */
final class ScimServer
{
    private const CORE_USER_SCHEMA  = 'urn:ietf:params:scim:schemas:core:2.0:User';
    private const CORE_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    private const LIST_SCHEMA       = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
    private const ERROR_SCHEMA      = 'urn:ietf:params:scim:api:messages:2.0:Error';
    private const MAX_RESULTS       = 100;
    private const MAX_BODY_BYTES    = 1048576;

    private Idp $idp;
    private string $base_url;

    public static function run(): void
    {
        try {
            $server = new self();
            $server->dispatch();
        } catch (ScimError $e) {
            self::error($e->status, $e->getMessage(), $e->scim_type);
        } catch (\Throwable $e) {
            Log::record('scim_error', Log::LEVEL_ERROR, 'unhandled SCIM error: ' . $e->getMessage());
            self::error(500, 'Internal server error');
        }
    }

    private function __construct()
    {
        $this->idp = self::authenticate();
        $this->base_url = Config::baseUrl() . '/plugins/sso/front/scim.php/v2';
    }

    private static function authenticate(): Idp
    {
        global $DB;

        $header = trim((string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
        if ($header === '' && function_exists('getallheaders')) {
            foreach ((array) getallheaders() as $name => $value) {
                if (strcasecmp((string) $name, 'Authorization') === 0) {
                    $header = trim((string) $value);
                    break;
                }
            }
        }
        if (!preg_match('/^Bearer\s+([^\s]+)$/i', $header, $match)) {
            throw new ScimError(401, 'Missing or invalid Bearer token');
        }

        $candidate = hash('sha256', (string) $match[1]);
        foreach ($DB->request([
            'SELECT' => ['id', 'scim_token_hash'],
            'FROM'   => Idp::getTable(),
            'WHERE'  => ['scim_enabled' => 1, 'is_active' => 1, 'is_deleted' => 0],
        ]) as $row) {
            $stored = (string) $row['scim_token_hash'];
            if ($stored !== '' && hash_equals($stored, $candidate)) {
                $idp = new Idp();
                if ($idp->getFromDB((int) $row['id'])) {
                    return $idp;
                }
            }
        }

        Log::record('scim_auth_failed', Log::LEVEL_WARNING, 'SCIM Bearer rejected');
        throw new ScimError(401, 'Invalid Bearer token');
    }

    private function dispatch(): void
    {
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($method === 'OPTIONS') {
            self::respond(null, 204);
            return;
        }

        $path = self::pathInfo();
        if ($path === '/v2/ServiceProviderConfig' && $method === 'GET') {
            self::respond($this->serviceProviderConfig());
            return;
        }
        if ($path === '/v2/ResourceTypes' && $method === 'GET') {
            self::respond($this->resourceTypes());
            return;
        }
        if ($path === '/v2/Schemas' && $method === 'GET') {
            self::respond($this->schemas());
            return;
        }

        if ($path === '/v2/Users') {
            $this->usersCollection($method);
            return;
        }
        if (preg_match('#^/v2/Users/(\d+)$#', $path, $match)) {
            $this->userResource($method, (int) $match[1]);
            return;
        }
        if ($path === '/v2/Groups') {
            $this->groupsCollection($method);
            return;
        }
        if (preg_match('#^/v2/Groups/(\d+)$#', $path, $match)) {
            $this->groupResource($method, (int) $match[1]);
            return;
        }

        throw new ScimError(404, 'SCIM resource not found');
    }

    private static function pathInfo(): string
    {
        $path = (string) ($_SERVER['PATH_INFO'] ?? '');
        if ($path === '') {
            $uri = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? '');
            $marker = '/scim.php';
            $position = strpos($uri, $marker);
            if ($position !== false) {
                $path = substr($uri, $position + strlen($marker));
            }
        }
        $path = '/' . ltrim($path, '/');
        return rtrim($path, '/') ?: '/';
    }

    private function usersCollection(string $method): void
    {
        if ($method === 'GET') {
            $this->listUsers();
            return;
        }
        if ($method === 'POST') {
            $this->createUser(self::body());
            return;
        }
        throw new ScimError(405, 'Method not allowed');
    }

    private function userResource(string $method, int $users_id): void
    {
        [$link, $user] = $this->ownedUser($users_id);
        if ($method === 'GET') {
            self::respond($this->userDocument($link, $user));
            return;
        }
        if ($method === 'PUT') {
            $this->updateUser($link, $user, self::body(), false);
            return;
        }
        if ($method === 'PATCH') {
            $this->patchUser($link, $user, self::body());
            return;
        }
        if ($method === 'DELETE') {
            $this->deleteUser($link, $user);
            return;
        }
        throw new ScimError(405, 'Method not allowed');
    }

    private function listUsers(): void
    {
        global $DB;

        $filter = trim((string) ($_GET['filter'] ?? ''));
        $wanted = $filter === '' ? null : self::parseEqFilter($filter, ['userName', 'externalId']);
        $rows = [];
        foreach ($DB->request([
            'FROM'  => UserLink::getTable(),
            'WHERE' => ['idps_id' => (int) $this->idp->getID()],
            'ORDER' => 'id',
        ]) as $link) {
            $user = new User();
            if (!$user->getFromDB((int) $link['users_id']) || (int) $user->fields['is_deleted'] === 1) {
                continue;
            }
            if ($wanted !== null) {
                [$field, $value] = $wanted;
                $actual = $field === 'userName' ? (string) $user->fields['name'] : (string) $link['subject'];
                if ($actual !== $value) {
                    continue;
                }
            }
            $rows[] = $this->userDocument($link, $user);
        }
        self::respond(self::page($rows));
    }

    private function createUser(array $body): void
    {
        global $DB;

        $login = trim((string) ($body['userName'] ?? ''));
        if ($login === '') {
            throw new ScimError(400, 'userName is required', 'invalidValue');
        }
        if (mb_strlen($login) > 255) {
            throw new ScimError(400, 'userName is too long', 'invalidValue');
        }
        $subject = trim((string) ($body['externalId'] ?? $login));
        if ($subject === '' || mb_strlen($subject) > 191) {
            throw new ScimError(400, 'externalId is invalid', 'invalidValue');
        }
        if ($this->linkBySubject($subject) !== null) {
            throw new ScimError(409, 'externalId already exists', 'uniqueness');
        }
        $existing = new User();
        if ($existing->getFromDBbyName($login)) {
            throw new ScimError(409, 'userName already exists', 'uniqueness');
        }

        $input = [
            'name'        => $login,
            'realname'    => trim((string) ($body['name']['familyName'] ?? '')),
            'firstname'   => trim((string) ($body['name']['givenName'] ?? '')),
            'phone'       => self::multiValue($body, 'phoneNumbers'),
            'authtype'    => GlpiAuth::EXTERNAL,
            'auths_id'    => 0,
            'is_active'   => array_key_exists('active', $body) ? (int) self::boolValue($body['active']) : 1,
            'is_deleted'  => 0,
            'entities_id' => (int) $this->idp->fields['default_entities_id'],
            'comment'     => 'Provisioned by SCIM IdP #' . (int) $this->idp->getID(),
        ];
        $user = new User();
        $users_id = (int) $user->add($input);
        if ($users_id <= 0) {
            throw new ScimError(500, 'Unable to create GLPI user');
        }

        if (!UserLink::link((int) $this->idp->getID(), $subject, $users_id, false)) {
            $user->delete(['id' => $users_id], true);
            throw new ScimError(500, 'Unable to create identity link');
        }
        $this->syncEmails($users_id, self::emails($body));
        $this->ensureDefaultProfile($users_id);

        $link = $this->linkByUser($users_id);
        $user->getFromDB($users_id);
        Log::record('scim_user_created', Log::LEVEL_INFO, 'user provisioned by SCIM: ' . $login, [
            'idps_id' => (int) $this->idp->getID(), 'users_id' => $users_id,
        ]);
        self::respond($this->userDocument($link, $user), 201, $this->base_url . '/Users/' . $users_id);
    }

    private function updateUser(array $link, User $user, array $body, bool $partial): void
    {
        $users_id = (int) $user->getID();
        $update = ['id' => $users_id];
        if (array_key_exists('userName', $body)) {
            $login = trim((string) $body['userName']);
            if ($login === '') {
                throw new ScimError(400, 'userName cannot be empty', 'invalidValue');
            }
            if ($login !== (string) $user->fields['name']) {
                $collision = new User();
                if ($collision->getFromDBbyName($login) && (int) $collision->getID() !== $users_id) {
                    throw new ScimError(409, 'userName already exists', 'uniqueness');
                }
                $update['name'] = $login;
            }
        } elseif (!$partial) {
            throw new ScimError(400, 'userName is required', 'invalidValue');
        }
        if (isset($body['externalId']) && (string) $body['externalId'] !== (string) $link['subject']) {
            throw new ScimError(400, 'externalId is immutable', 'mutability');
        }
        if (isset($body['name']) && is_array($body['name'])) {
            if (array_key_exists('familyName', $body['name'])) {
                $update['realname'] = trim((string) $body['name']['familyName']);
            }
            if (array_key_exists('givenName', $body['name'])) {
                $update['firstname'] = trim((string) $body['name']['givenName']);
            }
        }
        if (array_key_exists('phoneNumbers', $body)) {
            $update['phone'] = self::multiValue($body, 'phoneNumbers');
        }
        $deactivate = false;
        if (array_key_exists('active', $body)) {
            $active = (int) self::boolValue($body['active']);
            $deactivate = $active === 0 && (int) $user->fields['is_active'] === 1;
            $update['is_active'] = $active;
        }

        if (count($update) > 1 && !$user->update($update)) {
            throw new ScimError(500, 'Unable to update GLPI user');
        }
        if (array_key_exists('emails', $body)) {
            $this->syncEmails($users_id, self::emails($body));
        }
        $sessions = $deactivate ? self::invalidateSessions($users_id) : 0;

        $user->getFromDB($users_id);
        Log::record('scim_user_updated', Log::LEVEL_INFO, 'user updated by SCIM: ' . $user->fields['name'], [
            'idps_id' => (int) $this->idp->getID(), 'users_id' => $users_id,
            'sessions_invalidated' => $sessions,
        ]);
        self::respond($this->userDocument($link, $user));
    }

    private function patchUser(array $link, User $user, array $body): void
    {
        $this->updateUser($link, $user, ScimParser::parseUserPatch($body), true);
    }

    private function deleteUser(array $link, User $user): void
    {
        $users_id = (int) $user->getID();
        if (!$user->update(['id' => $users_id, 'is_active' => 0, 'is_deleted' => 1])) {
            throw new ScimError(500, 'Unable to deactivate GLPI user');
        }
        $sessions = self::invalidateSessions($users_id);
        Log::record('scim_user_deleted', Log::LEVEL_INFO, 'user soft-deleted by SCIM', [
            'idps_id' => (int) $this->idp->getID(), 'users_id' => $users_id,
            'sessions_invalidated' => $sessions,
        ]);
        self::respond(null, 204);
    }

    /** @return array{0:array,1:User} */
    private function ownedUser(int $users_id): array
    {
        $link = $this->linkByUser($users_id);
        $user = new User();
        if ($link === null || !$user->getFromDB($users_id) || (int) $user->fields['is_deleted'] === 1) {
            throw new ScimError(404, 'User not found');
        }
        return [$link, $user];
    }

    private function linkByUser(int $users_id): ?array
    {
        global $DB;
        foreach ($DB->request([
            'FROM' => UserLink::getTable(),
            'WHERE' => ['idps_id' => (int) $this->idp->getID(), 'users_id' => $users_id],
            'LIMIT' => 1,
        ]) as $row) {
            return $row;
        }
        return null;
    }

    private function linkBySubject(string $subject): ?array
    {
        global $DB;
        foreach ($DB->request([
            'FROM' => UserLink::getTable(),
            'WHERE' => ['idps_id' => (int) $this->idp->getID(), 'subject' => $subject],
            'LIMIT' => 1,
        ]) as $row) {
            return $row;
        }
        return null;
    }

    private function userDocument(array $link, User $user): array
    {
        global $DB;
        $emails = [];
        foreach ($DB->request([
            'FROM' => 'glpi_useremails', 'WHERE' => ['users_id' => (int) $user->getID()],
            'ORDER' => ['is_default DESC', 'id ASC'],
        ]) as $row) {
            if (trim((string) $row['email']) !== '') {
                $emails[] = ['value' => (string) $row['email'], 'primary' => (bool) $row['is_default']];
            }
        }
        $groups = [];
        foreach ($this->ownedGroupMaps() as $map) {
            if (countElementsInTable('glpi_groups_users', [
                'groups_id' => (int) $map['groups_id'], 'users_id' => (int) $user->getID(),
            ]) > 0) {
                $groups[] = ['value' => (string) $map['id'], 'display' => (string) $map['display_name']];
            }
        }
        $created = (string) ($link['date_creation'] ?? $user->fields['date_creation'] ?? '');
        $modified = (string) ($user->fields['date_mod'] ?? $created);
        $doc = [
            'schemas'   => [self::CORE_USER_SCHEMA],
            'id'        => (string) $user->getID(),
            'externalId'=> (string) $link['subject'],
            'userName'  => (string) $user->fields['name'],
            'name'      => [
                'familyName' => (string) $user->fields['realname'],
                'givenName'  => (string) $user->fields['firstname'],
            ],
            'active'    => (bool) $user->fields['is_active'],
            'emails'    => $emails,
            'groups'    => $groups,
            'meta'      => [
                'resourceType' => 'User', 'created' => self::iso($created),
                'lastModified' => self::iso($modified),
                'location' => $this->base_url . '/Users/' . (int) $user->getID(),
            ],
        ];
        if (trim((string) $user->fields['phone']) !== '') {
            $doc['phoneNumbers'] = [['value' => (string) $user->fields['phone'], 'primary' => true]];
        }
        return $doc;
    }

    private function syncEmails(int $users_id, array $emails): void
    {
        global $DB;
        $DB->delete('glpi_useremails', ['users_id' => $users_id, 'is_dynamic' => 1]);
        $seen = [];
        foreach ($emails as $index => $email) {
            $email = strtolower(trim((string) $email));
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || isset($seen[$email])) {
                continue;
            }
            $seen[$email] = true;
            if (countElementsInTable('glpi_useremails', ['users_id' => $users_id, 'email' => $email]) === 0) {
                (new UserEmail())->add([
                    'users_id' => $users_id, 'email' => $email,
                    'is_default' => $index === 0 ? 1 : 0, 'is_dynamic' => 1,
                ]);
            }
        }
    }

    private function ensureDefaultProfile(int $users_id): void
    {
        $profiles_id = (int) $this->idp->fields['default_profiles_id'];
        if ($profiles_id <= 0) {
            return;
        }
        $where = [
            'users_id' => $users_id, 'profiles_id' => $profiles_id,
            'entities_id' => (int) $this->idp->fields['default_entities_id'],
        ];
        if (countElementsInTable('glpi_profiles_users', $where) === 0) {
            (new Profile_User())->add($where + ['is_recursive' => 0, 'is_dynamic' => 1]);
        }
    }

    private function groupsCollection(string $method): void
    {
        if ($method === 'GET') {
            $this->listGroups();
            return;
        }
        if ($method === 'POST') {
            $this->createGroup(self::body());
            return;
        }
        throw new ScimError(405, 'Method not allowed');
    }

    private function groupResource(string $method, int $scim_groups_id): void
    {
        [$map, $group] = $this->ownedGroup($scim_groups_id);
        if ($method === 'GET') {
            self::respond($this->groupDocument($map, $group));
            return;
        }
        if ($method === 'PUT') {
            $this->updateGroup($map, $group, self::body(), false);
            return;
        }
        if ($method === 'PATCH') {
            $this->patchGroup($map, $group, self::body());
            return;
        }
        if ($method === 'DELETE') {
            $this->deleteGroup($map, $group);
            return;
        }
        throw new ScimError(405, 'Method not allowed');
    }

    private function listGroups(): void
    {
        $filter = trim((string) ($_GET['filter'] ?? ''));
        $wanted = $filter === '' ? null : self::parseEqFilter($filter, ['displayName', 'externalId']);
        $rows = [];
        foreach ($this->ownedGroupMaps() as $map) {
            if ($wanted !== null) {
                [$field, $value] = $wanted;
                $actual = $field === 'displayName' ? (string) $map['display_name'] : (string) $map['external_id'];
                if ($actual !== $value) {
                    continue;
                }
            }
            $group = new Group();
            if ($group->getFromDB((int) $map['groups_id'])) {
                $rows[] = $this->groupDocument($map, $group);
            }
        }
        self::respond(self::page($rows));
    }

    private function createGroup(array $body): void
    {
        global $DB;
        $display_name = trim((string) ($body['displayName'] ?? ''));
        if ($display_name === '') {
            throw new ScimError(400, 'displayName is required', 'invalidValue');
        }
        $external_id = trim((string) ($body['externalId'] ?? $display_name));
        if ($external_id === '' || mb_strlen($external_id) > 191) {
            throw new ScimError(400, 'externalId is invalid', 'invalidValue');
        }
        foreach ($this->ownedGroupMaps() as $row) {
            if ((string) $row['external_id'] === $external_id) {
                throw new ScimError(409, 'externalId already exists', 'uniqueness');
            }
        }
        $members = $this->memberIds((array) ($body['members'] ?? []));
        $group = new Group();
        $groups_id = (int) $group->add([
            'name' => $display_name,
            'entities_id' => (int) $this->idp->fields['default_entities_id'],
            'groups_id' => 0, 'is_recursive' => 0,
            'comment' => 'Managed by SCIM IdP #' . (int) $this->idp->getID(),
        ]);
        if ($groups_id <= 0) {
            throw new ScimError(409, 'Unable to create GLPI group (name may already exist)', 'uniqueness');
        }
        $now = date('Y-m-d H:i:s');
        if (!$DB->insert(ScimGroup::getTable(), [
            'idps_id' => (int) $this->idp->getID(), 'groups_id' => $groups_id,
            'external_id' => $external_id, 'date_creation' => $now, 'date_mod' => $now,
        ])) {
            $group->delete(['id' => $groups_id], true);
            throw new ScimError(500, 'Unable to create SCIM group mapping');
        }
        $map = $this->groupMapByCoreId($groups_id);
        $this->replaceGroupMembers($groups_id, $members);
        $group->getFromDB($groups_id);
        Log::record('scim_group_created', Log::LEVEL_INFO, 'group created by SCIM: ' . $display_name, [
            'idps_id' => (int) $this->idp->getID(), 'groups_id' => $groups_id,
        ]);
        self::respond($this->groupDocument($map, $group), 201, $this->base_url . '/Groups/' . (int) $map['id']);
    }

    private function updateGroup(array $map, Group $group, array $body, bool $partial): void
    {
        global $DB;
        $display_name = array_key_exists('displayName', $body)
            ? trim((string) $body['displayName']) : (string) $group->fields['name'];
        if ($display_name === '' && !$partial) {
            throw new ScimError(400, 'displayName is required', 'invalidValue');
        }
        if (isset($body['externalId']) && (string) $body['externalId'] !== (string) $map['external_id']) {
            throw new ScimError(400, 'externalId is immutable', 'mutability');
        }
        if ($display_name !== '' && $display_name !== (string) $group->fields['name']) {
            if (!$group->update(['id' => (int) $group->getID(), 'name' => $display_name])) {
                throw new ScimError(409, 'Unable to rename GLPI group', 'uniqueness');
            }
        }
        if (array_key_exists('members', $body)) {
            $this->replaceGroupMembers((int) $group->getID(), $this->memberIds((array) $body['members']));
        }
        $DB->update(ScimGroup::getTable(), ['date_mod' => date('Y-m-d H:i:s')], ['id' => (int) $map['id']]);
        $map = $this->groupMap((int) $map['id']);
        $group->getFromDB((int) $group->getID());
        Log::record('scim_group_updated', Log::LEVEL_INFO, 'group updated by SCIM', [
            'idps_id' => (int) $this->idp->getID(), 'groups_id' => (int) $group->getID(),
        ]);
        self::respond($this->groupDocument($map, $group));
    }

    private function patchGroup(array $map, Group $group, array $body): void
    {
        $display = null;
        foreach (ScimParser::parseGroupPatch($body) as $parsed) {
            switch ($parsed['kind']) {
                case 'display':
                    $display = $parsed['value'];
                    break;
                case 'members':
                    $ids = $this->memberIds($parsed['members']);
                    if ($parsed['op'] === 'add') {
                        $this->addGroupMembers((int) $group->getID(), $ids);
                    } elseif ($parsed['op'] === 'remove') {
                        $this->removeGroupMembers((int) $group->getID(), $ids);
                    } else {
                        $this->replaceGroupMembers((int) $group->getID(), $ids);
                    }
                    break;
                case 'remove_member':
                    $this->removeGroupMembers((int) $group->getID(), [$parsed['users_id']]);
                    break;
            }
        }
        $this->updateGroup($map, $group, $display === null ? [] : ['displayName' => $display], true);
    }

    private function deleteGroup(array $map, Group $group): void
    {
        global $DB;
        $groups_id = (int) $group->getID();
        $DB->delete('glpi_groups_users', ['groups_id' => $groups_id, 'is_dynamic' => 1]);
        if (!$group->delete(['id' => $groups_id], true)) {
            throw new ScimError(500, 'Unable to delete GLPI group');
        }
        $DB->delete(ScimGroup::getTable(), ['id' => (int) $map['id']]);
        Log::record('scim_group_deleted', Log::LEVEL_INFO, 'group deleted by SCIM', [
            'idps_id' => (int) $this->idp->getID(), 'groups_id' => $groups_id,
        ]);
        self::respond(null, 204);
    }

    /** @return array{0:array,1:Group} */
    private function ownedGroup(int $scim_groups_id): array
    {
        $map = $this->groupMap($scim_groups_id);
        $group = new Group();
        if ($map === null || !$group->getFromDB((int) $map['groups_id'])) {
            throw new ScimError(404, 'Group not found');
        }
        return [$map, $group];
    }

    private function groupMap(int $id): ?array
    {
        global $DB;
        foreach ($DB->request([
            'FROM' => ScimGroup::getTable(),
            'WHERE' => ['id' => $id, 'idps_id' => (int) $this->idp->getID()], 'LIMIT' => 1,
        ]) as $row) {
            return $row;
        }
        return null;
    }

    private function groupMapByCoreId(int $groups_id): ?array
    {
        global $DB;
        foreach ($DB->request([
            'FROM' => ScimGroup::getTable(),
            'WHERE' => ['groups_id' => $groups_id, 'idps_id' => (int) $this->idp->getID()], 'LIMIT' => 1,
        ]) as $row) {
            return $row;
        }
        return null;
    }

    /** @return array<int,array> */
    private function ownedGroupMaps(): array
    {
        global $DB;
        $maps = [];
        foreach ($DB->request([
            'FROM' => ScimGroup::getTable(),
            'WHERE' => ['idps_id' => (int) $this->idp->getID()], 'ORDER' => 'id',
        ]) as $row) {
            $group = new Group();
            if ($group->getFromDB((int) $row['groups_id'])) {
                $row['display_name'] = (string) $group->fields['name'];
                $maps[] = $row;
            }
        }
        return $maps;
    }

    private function groupDocument(array $map, Group $group): array
    {
        global $DB;
        $members = [];
        foreach ($DB->request([
            'FROM' => 'glpi_groups_users', 'WHERE' => ['groups_id' => (int) $group->getID()],
            'ORDER' => 'id',
        ]) as $membership) {
            if ($this->linkByUser((int) $membership['users_id']) !== null) {
                $members[] = ['value' => (string) $membership['users_id'],
                    '$ref' => $this->base_url . '/Users/' . (int) $membership['users_id']];
            }
        }
        return [
            'schemas' => [self::CORE_GROUP_SCHEMA], 'id' => (string) $map['id'],
            'externalId' => (string) $map['external_id'], 'displayName' => (string) $group->fields['name'],
            'members' => $members,
            'meta' => [
                'resourceType' => 'Group', 'created' => self::iso((string) $map['date_creation']),
                'lastModified' => self::iso((string) ($map['date_mod'] ?? $map['date_creation'])),
                'location' => $this->base_url . '/Groups/' . (int) $map['id'],
            ],
        ];
    }

    /** @return int[] */
    private function memberIds(array $members): array
    {
        $ids = [];
        foreach ($members as $member) {
            $id = (int) (is_array($member) ? ($member['value'] ?? 0) : $member);
            if ($id <= 0 || $this->linkByUser($id) === null) {
                throw new ScimError(400, 'Group member is not owned by this IdP: ' . $id, 'invalidValue');
            }
            $ids[$id] = $id;
        }
        return array_values($ids);
    }

    private function replaceGroupMembers(int $groups_id, array $users_ids): void
    {
        global $DB;
        $DB->delete('glpi_groups_users', ['groups_id' => $groups_id, 'is_dynamic' => 1]);
        $this->addGroupMembers($groups_id, $users_ids);
    }

    private function addGroupMembers(int $groups_id, array $users_ids): void
    {
        foreach ($users_ids as $users_id) {
            if (countElementsInTable('glpi_groups_users', [
                'groups_id' => $groups_id, 'users_id' => (int) $users_id,
            ]) === 0) {
                (new Group_User())->add([
                    'groups_id' => $groups_id, 'users_id' => (int) $users_id,
                    'is_dynamic' => 1, 'is_manager' => 0, 'is_userdelegate' => 0,
                ]);
            }
        }
    }

    private function removeGroupMembers(int $groups_id, array $users_ids): void
    {
        global $DB;
        if ($users_ids !== []) {
            $DB->delete('glpi_groups_users', [
                'groups_id' => $groups_id, 'users_id' => array_map('intval', $users_ids), 'is_dynamic' => 1,
            ]);
        }
    }

    private function serviceProviderConfig(): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'patch' => ['supported' => true], 'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => true, 'maxResults' => self::MAX_RESULTS],
            'changePassword' => ['supported' => false], 'sort' => ['supported' => false], 'etag' => ['supported' => false],
            'authenticationSchemes' => [[
                'type' => 'oauthbearertoken', 'name' => 'Bearer token',
                'description' => 'Per-IdP SCIM Bearer token', 'specUri' => 'https://www.rfc-editor.org/rfc/rfc6750',
                'primary' => true,
            ]],
        ];
    }

    private function resourceTypes(): array
    {
        return [
            'schemas' => [self::LIST_SCHEMA], 'totalResults' => 2, 'startIndex' => 1, 'itemsPerPage' => 2,
            'Resources' => [
                ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], 'id' => 'User',
                    'name' => 'User', 'endpoint' => '/Users', 'schema' => self::CORE_USER_SCHEMA],
                ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], 'id' => 'Group',
                    'name' => 'Group', 'endpoint' => '/Groups', 'schema' => self::CORE_GROUP_SCHEMA],
            ],
        ];
    }

    private function schemas(): array
    {
        return [
            'schemas' => [self::LIST_SCHEMA], 'totalResults' => 2, 'startIndex' => 1, 'itemsPerPage' => 2,
            'Resources' => [
                [
                    'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
                    'id' => self::CORE_USER_SCHEMA, 'name' => 'User', 'description' => 'SCIM User',
                    'attributes' => [
                        self::schemaAttribute('userName', 'string', false, true, 'server'),
                        self::schemaAttribute('externalId', 'string', false, false, 'server'),
                        self::schemaAttribute('name', 'complex', false, false, 'none', [
                            self::schemaAttribute('familyName', 'string'),
                            self::schemaAttribute('givenName', 'string'),
                        ]),
                        self::schemaAttribute('emails', 'complex', true, false, 'none', [
                            self::schemaAttribute('value', 'string'),
                            self::schemaAttribute('primary', 'boolean'),
                        ]),
                        self::schemaAttribute('phoneNumbers', 'complex', true, false, 'none', [
                            self::schemaAttribute('value', 'string'),
                            self::schemaAttribute('primary', 'boolean'),
                        ]),
                        self::schemaAttribute('active', 'boolean'),
                        self::schemaAttribute('groups', 'complex', true, false, 'none', [
                            self::schemaAttribute('value', 'string', false, false, 'none', [], 'readOnly'),
                            self::schemaAttribute('display', 'string', false, false, 'none', [], 'readOnly'),
                        ], 'readOnly'),
                    ],
                ],
                [
                    'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
                    'id' => self::CORE_GROUP_SCHEMA, 'name' => 'Group', 'description' => 'SCIM Group',
                    'attributes' => [
                        self::schemaAttribute('displayName', 'string', false, true),
                        self::schemaAttribute('externalId', 'string', false, false, 'server'),
                        self::schemaAttribute('members', 'complex', true, false, 'none', [
                            self::schemaAttribute('value', 'string'),
                            self::schemaAttribute('$ref', 'reference'),
                        ]),
                    ],
                ],
            ],
        ];
    }

    private static function schemaAttribute(
        string $name,
        string $type,
        bool $multi_valued = false,
        bool $required = false,
        string $uniqueness = 'none',
        array $sub_attributes = [],
        string $mutability = 'readWrite'
    ): array {
        $attribute = [
            'name' => $name, 'type' => $type, 'multiValued' => $multi_valued,
            'required' => $required, 'caseExact' => false, 'mutability' => $mutability,
            'returned' => 'default', 'uniqueness' => $uniqueness,
        ];
        if ($sub_attributes !== []) {
            $attribute['subAttributes'] = $sub_attributes;
        }
        return $attribute;
    }

    private static function body(): array
    {
        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > self::MAX_BODY_BYTES) {
            throw new ScimError(413, 'Request body too large');
        }
        $raw = (string) file_get_contents('php://input');
        if ($raw === '' || strlen($raw) > self::MAX_BODY_BYTES) {
            throw new ScimError(400, 'A JSON request body is required', 'invalidSyntax');
        }
        try {
            $body = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ScimError(400, 'Invalid JSON request body', 'invalidSyntax');
        }
        if (!is_array($body)) {
            throw new ScimError(400, 'JSON body must be an object', 'invalidSyntax');
        }
        return $body;
    }

    /** @return array{0:string,1:string} */
    private static function parseEqFilter(string $filter, array $allowed): array
    {
        return ScimParser::parseEqFilter($filter, $allowed);
    }

    private static function page(array $rows): array
    {
        $total = count($rows);
        $start = max(1, (int) ($_GET['startIndex'] ?? 1));
        $count = min(self::MAX_RESULTS, max(0, (int) ($_GET['count'] ?? self::MAX_RESULTS)));
        $page = $count === 0 ? [] : array_slice($rows, $start - 1, $count);
        return [
            'schemas' => [self::LIST_SCHEMA], 'totalResults' => $total,
            'startIndex' => $start, 'itemsPerPage' => count($page), 'Resources' => array_values($page),
        ];
    }

    /** @return string[] */
    private static function emails(array $body): array
    {
        $values = [];
        foreach ((array) ($body['emails'] ?? []) as $email) {
            $value = is_array($email) ? ($email['value'] ?? '') : $email;
            if (trim((string) $value) !== '') {
                $values[] = (string) $value;
            }
        }
        return $values;
    }

    private static function multiValue(array $body, string $field): string
    {
        foreach ((array) ($body[$field] ?? []) as $entry) {
            $value = is_array($entry) ? ($entry['value'] ?? '') : $entry;
            if (trim((string) $value) !== '') {
                return trim((string) $value);
            }
        }
        return '';
    }

    private static function boolValue(mixed $value): bool
    {
        return ScimParser::boolValue($value);
    }

    private static function iso(string $date): string
    {
        $timestamp = strtotime($date);
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp !== false ? $timestamp : time());
    }

    /** Best-effort: invalida archivos de sesión PHP que pertenecen al usuario. */
    private static function invalidateSessions(int $users_id): int
    {
        if (!defined('GLPI_SESSION_DIR') || !is_dir(GLPI_SESSION_DIR)) {
            return 0;
        }
        $removed = 0;
        foreach (glob(GLPI_SESSION_DIR . '/sess_*') ?: [] as $file) {
            if (!is_file($file) || !is_readable($file)) {
                continue;
            }
            $data = @file_get_contents($file);
            if (!is_string($data)) {
                continue;
            }
            $matches = str_contains($data, 'glpiID|i:' . $users_id . ';')
                || str_contains($data, 's:6:"glpiID";i:' . $users_id . ';');
            if ($matches && @unlink($file)) {
                $removed++;
            }
        }
        return $removed;
    }

    private static function respond(?array $payload, int $status = 200, string $location = ''): void
    {
        http_response_code($status);
        header('Content-Type: application/scim+json; charset=utf-8');
        header('Cache-Control: no-store');
        if ($location !== '') {
            header('Location: ' . $location);
        }
        if ($payload !== null && $status !== 204) {
            echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        }
    }

    private static function error(int $status, string $detail, string $scim_type = ''): void
    {
        if ($status === 401) {
            header('WWW-Authenticate: Bearer realm="GLPI SCIM"');
        }
        $payload = ['schemas' => [self::ERROR_SCHEMA], 'detail' => $detail, 'status' => (string) $status];
        if ($scim_type !== '') {
            $payload['scimType'] = $scim_type;
        }
        self::respond($payload, $status);
    }
}

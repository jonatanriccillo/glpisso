<?php

namespace GlpiPlugin\Sso;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Parsers SCIM puros (sin DB, sin $_GET): filtros, booleanos y PATCH.
 * Extraídos de ScimServer para poder testearlos unitariamente; el server
 * ejecuta lo que estos parsers devuelven. Comportamiento idéntico al
 * original verificado por la suite E2E.
 */
final class ScimParser
{
    public const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

    /**
     * Filtro `atributo eq "valor"` (lo único soportado). Devuelve el
     * atributo canónico (según $allowed, case-insensitive) y el valor
     * des-escapado JSON.
     *
     * @return array{0:string,1:string}
     * @throws ScimError
     */
    public static function parseEqFilter(string $filter, array $allowed): array
    {
        if (!preg_match('/^([A-Za-z][A-Za-z0-9.]*)\s+eq\s+"((?:[^"\\\\]|\\\\.)*)"$/i', $filter, $match)) {
            throw new ScimError(400, 'Only attribute eq "value" filters are supported', 'invalidFilter');
        }
        $field = null;
        foreach ($allowed as $candidate) {
            if (strcasecmp($candidate, $match[1]) === 0) {
                $field = $candidate;
                break;
            }
        }
        if ($field === null) {
            throw new ScimError(400, 'Unsupported filter attribute', 'invalidFilter');
        }
        $value = json_decode('"' . $match[2] . '"', true);
        return [$field, is_string($value) ? $value : $match[2]];
    }

    /**
     * Booleano SCIM tolerante: los clientes reales mandan true/false JSON,
     * enteros o strings "True"/"False" — pero "False" JAMÁS es truthy.
     *
     * @throws ScimError
     */
    public static function boolValue(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value)) {
            return $value !== 0;
        }
        $normalized = strtolower(trim((string) $value));
        if (in_array($normalized, ['true', '1'], true)) {
            return true;
        }
        if (in_array($normalized, ['false', '0'], true)) {
            return false;
        }
        throw new ScimError(400, 'active must be a boolean', 'invalidValue');
    }

    /**
     * PATCH de User → array de cambios estilo body (mismo shape que un
     * PUT parcial). Paths soportados: userName, active, name.givenName,
     * name.familyName, emails, phoneNumbers y path vacío con objeto.
     *
     * @throws ScimError
     */
    public static function parseUserPatch(array $body): array
    {
        if (!in_array(self::PATCH_SCHEMA, (array) ($body['schemas'] ?? []), true)) {
            throw new ScimError(400, 'PatchOp schema is required', 'invalidSyntax');
        }
        $changes = [];
        foreach ((array) ($body['Operations'] ?? []) as $operation) {
            if (!is_array($operation)) {
                throw new ScimError(400, 'Invalid PATCH operation', 'invalidSyntax');
            }
            $op = strtolower((string) ($operation['op'] ?? ''));
            $path = strtolower(trim((string) ($operation['path'] ?? '')));
            $value = $operation['value'] ?? null;
            if (!in_array($op, ['add', 'replace', 'remove'], true)) {
                throw new ScimError(400, 'Unsupported PATCH operation', 'invalidSyntax');
            }
            if ($path === '' && is_array($value)) {
                $changes = array_replace_recursive($changes, $value);
                continue;
            }
            $remove = $op === 'remove';
            switch ($path) {
                case 'username': $changes['userName'] = $remove ? '' : $value; break;
                case 'active': $changes['active'] = $remove ? false : self::boolValue($value); break;
                case 'name.givenname': $changes['name']['givenName'] = $remove ? '' : $value; break;
                case 'name.familyname': $changes['name']['familyName'] = $remove ? '' : $value; break;
                case 'emails': $changes['emails'] = $remove ? [] : $value; break;
                case 'phonenumbers': $changes['phoneNumbers'] = $remove ? [] : $value; break;
                default: throw new ScimError(400, 'Unsupported PATCH path: ' . $path, 'invalidPath');
            }
        }
        return $changes;
    }

    /**
     * PATCH de Group → lista ORDENADA de operaciones a ejecutar:
     *   ['kind' => 'display', 'value' => string]
     *   ['kind' => 'members', 'op' => add|remove|replace, 'members' => array]
     *   ['kind' => 'remove_member', 'users_id' => int]
     *
     * @return array<int, array>
     * @throws ScimError
     */
    public static function parseGroupPatch(array $body): array
    {
        if (!in_array(self::PATCH_SCHEMA, (array) ($body['schemas'] ?? []), true)) {
            throw new ScimError(400, 'PatchOp schema is required', 'invalidSyntax');
        }
        $ops = [];
        foreach ((array) ($body['Operations'] ?? []) as $operation) {
            $op = strtolower((string) ($operation['op'] ?? ''));
            $path = strtolower(trim((string) ($operation['path'] ?? '')));
            $value = $operation['value'] ?? null;
            if (!in_array($op, ['add', 'replace', 'remove'], true)) {
                throw new ScimError(400, 'Unsupported PATCH operation', 'invalidSyntax');
            }
            if ($path === 'displayname') {
                if ($op === 'remove') {
                    throw new ScimError(400, 'displayName cannot be removed', 'mutability');
                }
                $ops[] = ['kind' => 'display', 'value' => (string) $value];
                continue;
            }
            if ($path === 'members' || ($path === '' && is_array($value) && isset($value['members']))) {
                $members = $path === 'members' ? (array) $value : (array) $value['members'];
                $ops[] = ['kind' => 'members', 'op' => $op, 'members' => $members];
                continue;
            }
            if ($op === 'remove' && preg_match('/^members\[value eq "(\d+)"\]$/', $path, $match)) {
                $ops[] = ['kind' => 'remove_member', 'users_id' => (int) $match[1]];
                continue;
            }
            throw new ScimError(400, 'Unsupported PATCH path: ' . $path, 'invalidPath');
        }
        return $ops;
    }
}

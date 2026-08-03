<?php

namespace GlpiPlugin\Sso;

use Entity;
use Group;
use Rule;
use Session;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Regla de autorización SSO sobre el engine nativo de GLPI (mismo modelo que
 * RuleRight). Se registra vía el alias corto `PluginSsoRuleAuth` (sub_type en
 * DB) y aparece en Administración > Reglas con la UI estándar completa.
 *
 * Semántica: se procesan TODAS las reglas en orden (acumulativo);
 * `_deny_login` corta. Ver LoginPipeline::applyRules para la aplicación.
 */
class RuleAuth extends Rule
{
    public static $rightname = 'plugin_sso';
    public $can_sort = true;

    public static function getTypeName($nb = 0)
    {
        return __('SSO authorization rules', 'sso');
    }

    public function getTitle()
    {
        return self::getTypeName();
    }

    public static function getIcon()
    {
        return 'ti ti-fingerprint';
    }

    /** Claims expuestos como criterios dinámicos (mapeados en IdPs activos). */
    private static function dynamicClaims(): array
    {
        $claims = ['department', 'title'];
        foreach (Idp::getActive() as $row) {
            $mapping = json_decode((string) ($row['claim_mapping'] ?? ''), true);
            if (is_array($mapping)) {
                foreach ($mapping as $mapped) {
                    if (is_scalar($mapped)) {
                        $claims[] = (string) $mapped;
                    }
                }
            }
        }
        return array_values(array_unique(array_filter($claims)));
    }

    public function getCriterias()
    {
        $criterias = [];
        $criterias['common'] = __('Global criteria');

        $criterias['_idps_id'] = [
            'table'     => Idp::getTable(),
            'field'     => 'name',
            'name'      => Idp::getTypeName(1),
            'linkfield' => '',
            'type'      => 'dropdown',
            'virtual'   => true,
            'id'        => 'idp',
        ];

        $text = fn(string $name, string $id) => [
            'table' => '', 'field' => '', 'name' => $name,
            'linkfield' => '', 'virtual' => true, 'id' => $id,
        ];

        $criterias['protocol']      = $text(__('Protocol', 'sso'), 'protocol');
        $criterias['login']         = $text(__('Login'), 'login');
        $criterias['email']         = $text(_n('Email', 'Emails', 1), 'email');
        $criterias['_email_domain'] = $text(__('Email domain', 'sso'), 'email_domain');
        $criterias['_groups']       = $text(__('Groups (IdP claim)', 'sso'), 'groups');
        $criterias['firstname']     = $text(__('First name'), 'firstname');
        $criterias['realname']      = $text(__('Surname'), 'realname');

        foreach (self::dynamicClaims() as $claim) {
            $criterias['claim_' . $claim] = $text(sprintf(__('Claim: %s', 'sso'), $claim), 'claim_' . $claim);
        }

        return $criterias;
    }

    public function getActions()
    {
        $actions = parent::getActions();

        $actions['entities_id']['name']  = Entity::getTypeName(1);
        $actions['entities_id']['type']  = 'dropdown';
        $actions['entities_id']['table'] = 'glpi_entities';

        $actions['profiles_id']['name']  = _n('Profile', 'Profiles', Session::getPluralNumber());
        $actions['profiles_id']['type']  = 'dropdown';
        $actions['profiles_id']['table'] = 'glpi_profiles';

        $actions['is_recursive']['name']  = __('Recursive');
        $actions['is_recursive']['type']  = 'yesno';
        $actions['is_recursive']['table'] = '';

        $actions['_groups_id_add']['name']      = __('Add to group', 'sso');
        $actions['_groups_id_add']['type']      = 'dropdown';
        $actions['_groups_id_add']['table']     = 'glpi_groups';
        $actions['_groups_id_add']['condition'] = ['is_usergroup' => 1];

        $actions['is_active']['name']  = __('Active');
        $actions['is_active']['type']  = 'yesno';
        $actions['is_active']['table'] = '';

        $actions['_entities_id_default']['name']      = __('Default entity');
        $actions['_entities_id_default']['type']      = 'dropdown_entity';
        $actions['_entities_id_default']['table']     = 'glpi_entities';
        $actions['_entities_id_default']['field']     = 'name';
        $actions['_entities_id_default']['linkfield'] = 'entities_id';

        $actions['_profiles_id_default']['name']      = __('Default profile');
        $actions['_profiles_id_default']['type']      = 'dropdown';
        $actions['_profiles_id_default']['table']     = 'glpi_profiles';
        $actions['_profiles_id_default']['field']     = 'name';
        $actions['_profiles_id_default']['linkfield'] = 'profiles_id';

        $actions['timezone']['name'] = __('Timezone');
        $actions['timezone']['type'] = 'timezone';

        $actions['language']['name'] = __('Language');
        $actions['language']['type'] = 'language';

        $actions['_deny_login']['name']  = __('Deny login', 'sso');
        $actions['_deny_login']['type']  = 'yesonly';
        $actions['_deny_login']['table'] = '';

        return $actions;
    }

    /**
     * Acumula en $output a través de TODAS las reglas que matchean (la
     * collection no corta en el primer match). Entidad/perfil/recursivo de
     * una misma regla van juntos como "grant"; los faltantes se completan
     * con los defaults del IdP en LoginPipeline.
     */
    public function executeActions($output, $params, array $input = [])
    {
        $entities  = [];
        $profiles  = [];
        $recursive = 0;

        foreach ($this->actions as $action) {
            $field = $action->fields['field'];
            $value = $action->fields['value'];
            switch ($field) {
                case 'entities_id':
                    $entities[] = (int) $value;
                    break;
                case 'profiles_id':
                    $profiles[] = (int) $value;
                    break;
                case 'is_recursive':
                    $recursive = (int) $value;
                    break;
                case '_groups_id_add':
                    $output['_sso_groups'][] = (int) $value;
                    break;
                case 'is_active':
                    $output['_sso_is_active'] = (int) $value;
                    break;
                case '_entities_id_default':
                    $output['_sso_default_entity'] = (int) $value;
                    break;
                case '_profiles_id_default':
                    $output['_sso_default_profile'] = (int) $value;
                    break;
                case 'timezone':
                    $output['_sso_timezone'] = (string) $value;
                    break;
                case 'language':
                    $output['_sso_language'] = (string) $value;
                    break;
                case '_deny_login':
                    $output['_sso_deny'] = true;
                    break;
            }
        }

        // Combos de ESTA regla (entidad sola, perfil solo, o cruzados).
        if ($entities !== [] || $profiles !== []) {
            $ents  = $entities !== [] ? $entities : [null];
            $profs = $profiles !== [] ? $profiles : [null];
            foreach ($ents as $e) {
                foreach ($profs as $p) {
                    $output['_sso_grants'][] = [
                        'entities_id'  => $e,
                        'profiles_id'  => $p,
                        'is_recursive' => $recursive,
                    ];
                }
            }
        }

        $output['_sso_matched'][] = (string) $this->fields['name'];
        return $output;
    }
}

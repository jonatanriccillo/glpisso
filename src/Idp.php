<?php

namespace GlpiPlugin\Sso;

use CommonDBTM;
use Dropdown;
use Entity;
use GLPIKey;
use Html;
use Session;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Proveedor de identidad configurado. El form ramifica por `protocol`
 * (saml/oidc) con un toggle JS, mismo patrón que webhooks/trigger_type.
 * Secretos (client_secret, sp_private_key) cifrados con GLPIKey.
 */
class Idp extends CommonDBTM
{
    public const ICON_GOOGLE = 'sso-brand-google';
    public const ICON_MICROSOFT = 'sso-brand-microsoft';

    public static $rightname = 'plugin_sso';
    public $dohistory = true;

    public const PROTO_SAML = 'saml';
    public const PROTO_OIDC = 'oidc';
    public const PROTOCOLS  = [self::PROTO_SAML, self::PROTO_OIDC];

    public const MATCHING_FIELDS = ['email', 'name'];
    public const RULES_MODES     = ['always', 'on_create_only'];
    public const LOGIN_PRESENTATIONS = ['button', 'icon'];
    public const SECRET_FIELDS   = ['client_secret', 'sp_private_key'];

    /** Mapeo claim→campo de glpi_users por defecto, por protocolo. */
    public const DEFAULT_MAPPING = [
        self::PROTO_OIDC => [
            'name'        => 'preferred_username',
            'realname'    => 'family_name',
            'firstname'   => 'given_name',
            '_useremails' => 'email',
            'phone'       => 'phone_number',
        ],
        self::PROTO_SAML => [
            'name'        => 'uid',
            'realname'    => 'sn',
            'firstname'   => 'givenName',
            '_useremails' => 'mail',
        ],
    ];

    public static function getTypeName($nb = 0)
    {
        return _n('Identity provider', 'Identity providers', $nb, 'sso');
    }

    public static function getIcon()
    {
        return 'ti ti-fingerprint';
    }

    public static function brandIconUrl(string $icon): ?string
    {
        $assets = [
            self::ICON_GOOGLE    => 'google.png',
            self::ICON_MICROSOFT => 'microsoft.svg',
        ];
        if (!isset($assets[$icon])) {
            return null;
        }

        return \Html::getPrefixedUrl('/plugins/sso/public/icons/' . $assets[$icon]);
    }

    public static function renderProviderIcon(string $icon): string
    {
        $asset_url = self::brandIconUrl($icon);
        if ($asset_url === null) {
            return "<i class='" . htmlspecialchars($icon, ENT_QUOTES, 'UTF-8') . "' aria-hidden='true'></i>";
        }

        return "<span class='sso-brand-icon-frame' aria-hidden='true'"
            . " style='display:inline-flex;width:1.5rem;height:1.5rem;align-items:center;justify-content:center;"
            . "flex:0 0 auto;margin-right:1rem;vertical-align:middle;background:#fff;border-radius:.25rem'>"
            . "<img class='sso-brand-icon' src='"
            . htmlspecialchars($asset_url, ENT_QUOTES, 'UTF-8')
            . "' alt='' width='18' height='18' decoding='async'"
            . " style='display:block;width:1.125rem;height:1.125rem;object-fit:contain'></span>";
    }

    public static function getMenuContent()
    {
        return Menu::getMenuContent();
    }

    public function defineTabs($options = [])
    {
        $ong = [];
        $this->addDefaultFormTab($ong);
        $this->addStandardTab(\Log::class, $ong, $options);
        return $ong;
    }

    public function post_getEmpty()
    {
        $this->fields['protocol']               = self::PROTO_SAML;
        $this->fields['is_active']              = 0;
        $this->fields['scopes']                 = 'openid profile email';
        $this->fields['require_email_verified'] = 1;
        $this->fields['nameid_format']          = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
        $this->fields['matching_field']         = 'email';
        $this->fields['groups_claim']           = 'groups';
        $this->fields['rules_mode']             = 'always';
        $this->fields['jit_create']             = 0;
        $this->fields['jit_update']             = 0;
        $this->fields['scim_enabled']            = 0;
        $this->fields['login_presentation']       = 'button';
        $this->fields['icon']                   = 'ti ti-certificate';
    }

    public function prepareInputForAdd($input)
    {
        return $this->prepareInput($input, true);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->prepareInput($input, false);
    }

    // Trim: un espacio de más al copiar rompe el login en silencio (ej. Google -> "invalid_client").
    private const TRIM_ON_SAVE = [
        'name', 'button_label',
        'issuer_url', 'client_id', 'scopes', 'groups_claim',
        'idp_entity_id', 'idp_sso_url', 'idp_slo_url',
        'idp_x509cert', 'idp_x509cert_rollover', 'sp_x509cert',
        'domain_allowlist',
    ];

    /** @return array|false */
    private function prepareInput(array $input, bool $add)
    {
        foreach (self::TRIM_ON_SAVE as $field) {
            if (isset($input[$field]) && is_string($input[$field])) {
                $input[$field] = trim($input[$field]);
            }
        }

        if ($add && ($input['name'] ?? '') === '') {
            Session::addMessageAfterRedirect(__('A name is required', 'sso'), false, ERROR);
            return false;
        }

        if (isset($input['protocol']) && !in_array($input['protocol'], self::PROTOCOLS, true)) {
            unset($input['protocol']);
        }
        if (isset($input['matching_field']) && !in_array($input['matching_field'], self::MATCHING_FIELDS, true)) {
            unset($input['matching_field']);
        }
        if (isset($input['rules_mode']) && !in_array($input['rules_mode'], self::RULES_MODES, true)) {
            unset($input['rules_mode']);
        }
        if (
            isset($input['login_presentation'])
            && !in_array($input['login_presentation'], self::LOGIN_PRESENTATIONS, true)
        ) {
            unset($input['login_presentation']);
        }
        if (array_key_exists('icon', $input)) {
            $icon = trim((string) $input['icon']);
            if ($icon === '') {
                $input['icon'] = ($input['protocol'] ?? ($this->fields['protocol'] ?? self::PROTO_SAML))
                    === self::PROTO_OIDC ? 'ti ti-circle-key' : 'ti ti-certificate';
            } elseif (!preg_match('/^[a-zA-Z0-9_-]+(?:\s+[a-zA-Z0-9_-]+)*$/', $icon)) {
                Session::addMessageAfterRedirect(__('The icon class contains invalid characters', 'sso'), false, ERROR);
                unset($input['icon']);
            } else {
                $input['icon'] = $icon;
            }
        }

        // Secretos: vacío = "sin cambios" (no pisa lo guardado); valor = cifrar.
        foreach (self::SECRET_FIELDS as $field) {
            if (!array_key_exists($field, $input)) {
                continue;
            }
            $value = trim((string) $input[$field]);
            if ($value === '') {
                unset($input[$field]);
            } else {
                $input[$field] = (new GLPIKey())->encrypt($value);
            }
        }

        // claim_mapping: validar JSON; vacío al crear = defaults del protocolo.
        if (array_key_exists('claim_mapping', $input)) {
            $raw = trim((string) $input['claim_mapping']);
            if ($raw === '') {
                $proto = $input['protocol'] ?? ($this->fields['protocol'] ?? self::PROTO_SAML);
                $input['claim_mapping'] = json_encode(self::DEFAULT_MAPPING[$proto], JSON_UNESCAPED_SLASHES);
            } else {
                $decoded = json_decode($raw, true);
                if (!is_array($decoded)) {
                    Session::addMessageAfterRedirect(__('Claim mapping must be valid JSON', 'sso'), false, ERROR);
                    unset($input['claim_mapping']);
                } else {
                    $input['claim_mapping'] = json_encode($decoded, JSON_UNESCAPED_SLASHES);
                }
            }
        } elseif ($add) {
            $proto = $input['protocol'] ?? self::PROTO_SAML;
            $input['claim_mapping'] = json_encode(self::DEFAULT_MAPPING[$proto], JSON_UNESCAPED_SLASHES);
        }

        return $input;
    }

    /** Descifra un secreto guardado ('' si no hay). */
    public function getSecret(string $field): string
    {
        if (!in_array($field, self::SECRET_FIELDS, true)) {
            return '';
        }
        $stored = (string) ($this->fields[$field] ?? '');
        if ($stored === '') {
            return '';
        }
        return (string) (new GLPIKey())->decrypt($stored);
    }

    /** Genera un Bearer SCIM y persiste únicamente su SHA-256. */
    public function generateScimToken(): string
    {
        global $DB;

        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $DB->update(self::getTable(), [
            'scim_token_hash' => hash('sha256', $token),
            'date_mod'        => date('Y-m-d H:i:s'),
        ], ['id' => (int) $this->getID()]);
        $this->fields['scim_token_hash'] = hash('sha256', $token);
        return $token;
    }

    /** Revoca inmediatamente el Bearer SCIM actual. */
    public function revokeScimToken(): void
    {
        global $DB;

        $DB->update(self::getTable(), [
            'scim_token_hash' => '',
            'date_mod'        => date('Y-m-d H:i:s'),
        ], ['id' => (int) $this->getID()]);
        $this->fields['scim_token_hash'] = '';
    }

    /** @return array<string, string> claim → campo de glpi_users */
    public function getClaimMapping(): array
    {
        $decoded = json_decode((string) ($this->fields['claim_mapping'] ?? ''), true);
        if (is_array($decoded) && $decoded !== []) {
            return $decoded;
        }
        return self::DEFAULT_MAPPING[$this->fields['protocol']] ?? self::DEFAULT_MAPPING[self::PROTO_SAML];
    }

    /** Dropdown de IdPs activos (para la config global / HRD). */
    public static function dropdownActive(string $name, int $value): void
    {
        global $DB;

        $options = [0 => Dropdown::EMPTY_VALUE];
        foreach ($DB->request([
            'SELECT' => ['id', 'name', 'protocol'],
            'FROM'   => self::getTable(),
            'WHERE'  => ['is_active' => 1, 'is_deleted' => 0],
            'ORDER'  => 'ranking',
        ]) as $row) {
            $options[(int) $row['id']] = $row['name'] . ' (' . strtoupper((string) $row['protocol']) . ')';
        }
        Dropdown::showFromArray($name, $options, ['value' => $value]);
    }

    /**
     * Filas COMPLETAS de los IdPs activos (SELECT *), orden por ranking.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getActive(): array
    {
        global $DB;

        $idps = [];
        foreach ($DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => ['is_active' => 1, 'is_deleted' => 0],
            'ORDER' => 'ranking',
        ]) as $row) {
            $idps[] = $row;
        }
        return $idps;
    }

    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            'id' => 2, 'table' => self::getTable(), 'field' => 'protocol',
            'name' => __('Protocol', 'sso'), 'datatype' => 'string',
        ];
        $tab[] = [
            'id' => 3, 'table' => self::getTable(), 'field' => 'is_active',
            'name' => __('Active'), 'datatype' => 'bool',
        ];
        $tab[] = [
            'id' => 4, 'table' => self::getTable(), 'field' => 'ranking',
            'name' => __('Ranking'), 'datatype' => 'number',
        ];
        $tab[] = [
            'id' => 5, 'table' => self::getTable(), 'field' => 'date_mod',
            'name' => __('Last update'), 'datatype' => 'datetime',
            'massiveaction' => false,
        ];

        return $tab;
    }

    private static function showFormSection(
        string $title,
        string $icon,
        string $classes = '',
        string $id = ''
    ): void {
        echo "<tr" . ($id !== '' ? " id='" . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . "'" : '')
            . " class='sso-section-row " . htmlspecialchars($classes, ENT_QUOTES, 'UTF-8') . "'>";
        echo "<td colspan='4'><div class='hr-text'>"
            . "<i class='" . htmlspecialchars($icon, ENT_QUOTES, 'UTF-8') . "'></i>"
            . "<span>" . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . "</span>"
            . "</div></td></tr>";
    }

    private static function openFormCard(string $classes = ''): void
    {
        echo "<tr class='sso-card-row " . htmlspecialchars($classes, ENT_QUOTES, 'UTF-8') . "'>";
        echo "<td colspan='4'><div class='card sso-section-card'><div class='card-body'>"
            . "<div class='row g-4'>";
    }

    private static function closeFormCard(): void
    {
        echo "</div></div></div></td></tr>";
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        $form_css_url = \Html::getPrefixedUrl('/plugins/sso/public/idp-form.css')
            . '?v=' . rawurlencode(PLUGIN_SSO_VERSION);
        echo "<link rel='stylesheet' href='"
            . htmlspecialchars($form_css_url, ENT_QUOTES, 'UTF-8') . "'>";

        $proto = $this->fields['protocol'];

        if ($ID > 0 && $proto === self::PROTO_SAML) {
            foreach (['idp_x509cert' => __('IdP certificate', 'sso'), 'sp_x509cert' => __('SP certificate', 'sso')] as $field => $label) {
                $pem = trim((string) $this->fields[$field]);
                if ($pem === '') {
                    continue;
                }
                $days = CertWatch::daysUntilExpiration($pem);
                if ($days !== null && $days <= CertWatch::WARN_DAYS) {
                    $msg = $days < 0
                        ? sprintf(__('%1$s expired %2$d days ago', 'sso'), $label, abs($days))
                        : sprintf(__('%1$s expires in %2$d days', 'sso'), $label, $days);
                    echo "<tr><td colspan='4'><div class='alert alert-" . ($days < 0 ? 'danger' : 'warning')
                        . "'><i class='ti ti-alert-triangle'></i> " . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8')
                        . "</div></td></tr>";
                }
            }
        }

        self::showFormSection(__('General settings', 'sso'), 'ti ti-adjustments', '', 'sso-idp-form-marker');
        self::openFormCard();
        echo "<div class='col-md-6 sso-form-field'>";
        echo "<label>" . __('Name') . " <span class='required'>*</span></label>";
        echo Html::input('name', ['value' => $this->fields['name'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-4 col-md-2 sso-form-field sso-field-compact'>";
        echo "<label>" . __('Active') . "</label>";
        Dropdown::showYesNo('is_active', (int) $this->fields['is_active']);
        echo "</div>";
        echo "<div class='col-4 col-md-2 sso-form-field sso-field-compact'>";
        echo "<label>" . __('Protocol', 'sso') . "</label>";
        Dropdown::showFromArray('protocol', [
            self::PROTO_SAML => __('SAML 2.0', 'sso'),
            self::PROTO_OIDC => __('OpenID Connect', 'sso'),
        ], [
            'value'     => $proto,
            'on_change' => 'ssoToggleProtocol(this.value, true)',
        ]);
        echo "</div>";
        echo "<div class='col-4 col-md-2 sso-form-field sso-field-compact'>";
        echo "<label>" . __('Ranking') . "</label>";
        Dropdown::showNumber('ranking', ['value' => (int) $this->fields['ranking'], 'min' => 0, 'max' => 100]);
        echo "</div>";
        self::closeFormCard();

        // ---------------- OIDC ----------------
        self::showFormSection(__('OpenID Connect', 'sso'), 'ti ti-circle-key', 'sso-proto sso-proto-oidc');
        self::openFormCard('sso-proto sso-proto-oidc');
        echo "<div class='col-md-8 sso-form-field'><label>" . __('Issuer URL (discovery)', 'sso') . "</label>";
        echo Html::input('issuer_url', ['value' => $this->fields['issuer_url'], 'class' => 'form-control',
            'placeholder' => 'https://idp.example.com/realms/mi-realm']);
        echo "</div>";
        echo "<div class='col-md-4 sso-form-field'><label>" . __('Scopes', 'sso') . "</label>";
        echo Html::input('scopes', ['value' => $this->fields['scopes'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Client ID', 'sso') . "</label>";
        echo Html::input('client_id', ['value' => $this->fields['client_id'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Client secret', 'sso') . "</label>";
        echo Html::input('client_secret', ['type' => 'password', 'value' => '', 'class' => 'form-control',
            'placeholder' => ($this->fields['client_secret'] ?? '') !== '' ? __('(unchanged)', 'sso') : '',
            'autocomplete' => 'new-password']);
        echo "</div>";
        echo "<div class='col-md-4 sso-form-field sso-field-compact'><label>"
            . __('Require verified email', 'sso') . "</label>";
        Dropdown::showYesNo('require_email_verified', (int) $this->fields['require_email_verified']);
        echo "</div>";
        if ($ID > 0) {
            $redirect_uri = Config::baseUrl() . '/plugins/sso/front/callback.php';
            echo "<div class='col-md-8 sso-form-field'><label>"
                . __('Redirect URI (register this in your IdP)', 'sso') . "</label>";
            echo "<div class='sso-readonly-value'><code>"
                . htmlspecialchars($redirect_uri, ENT_QUOTES, 'UTF-8') . "</code></div></div>";
        }
        self::closeFormCard();

        // ---------------- SAML ----------------
        self::showFormSection(__('SAML 2.0', 'sso'), 'ti ti-certificate', 'sso-proto sso-proto-saml');
        self::openFormCard('sso-proto sso-proto-saml');
        echo "<div class='col-md-6 sso-form-field'><label>" . __('IdP Entity ID', 'sso') . "</label>";
        echo Html::input('idp_entity_id', ['value' => $this->fields['idp_entity_id'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('NameID format', 'sso') . "</label>";
        echo Html::input('nameid_format', ['value' => $this->fields['nameid_format'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('IdP SSO URL', 'sso') . "</label>";
        echo Html::input('idp_sso_url', ['value' => $this->fields['idp_sso_url'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('IdP SLO URL', 'sso') . "</label>";
        echo Html::input('idp_slo_url', ['value' => $this->fields['idp_slo_url'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('IdP X.509 certificate', 'sso') . "</label>";
        echo "<textarea name='idp_x509cert' rows='5' class='form-control font-monospace'"
            . " placeholder='-----BEGIN CERTIFICATE-----'>"
            . htmlspecialchars((string) $this->fields['idp_x509cert'], ENT_QUOTES, 'UTF-8') . "</textarea></div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Rollover certificate (optional)', 'sso') . "</label>";
        echo "<textarea name='idp_x509cert_rollover' rows='5' class='form-control font-monospace'>"
            . htmlspecialchars((string) $this->fields['idp_x509cert_rollover'], ENT_QUOTES, 'UTF-8') . "</textarea></div>";
        echo "<div class='col-md-6 sso-form-field sso-field-compact'><label>"
            . __('Sign AuthnRequests', 'sso') . "</label>";
        Dropdown::showYesNo('sign_authn_requests', (int) $this->fields['sign_authn_requests']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field sso-field-compact'><label>"
            . __('Require encrypted assertions', 'sso') . "</label>";
        Dropdown::showYesNo('want_assertions_encrypted', (int) $this->fields['want_assertions_encrypted']);
        echo "</div>";

        if ($ID > 0 && $proto === self::PROTO_SAML) {
            $metadata_url = Config::baseUrl() . '/plugins/sso/front/metadata.php?idp=' . $ID;
            echo "<div class='col-md-6 sso-form-field'><label>"
                . __('SP metadata URL (register this in your IdP)', 'sso') . "</label>";
            echo "<div class='sso-readonly-value'><a href='"
                . htmlspecialchars($metadata_url, ENT_QUOTES, 'UTF-8') . "' target='_blank'>"
                . htmlspecialchars($metadata_url, ENT_QUOTES, 'UTF-8') . "</a></div></div>";
            echo "<div class='col-md-6 sso-form-field'><label>"
                . __('Import IdP metadata (XML or URL)', 'sso') . "</label>";
            echo "<textarea name='metadata_xml' rows='2' class='form-control'"
                . " placeholder='https://idp/.../descriptor'></textarea>";
            echo Html::submit(__('Import metadata', 'sso'), [
                'name' => 'import_metadata',
                'class' => 'btn btn-outline-secondary mt-2',
                'icon' => 'ti ti-file-import',
            ]);
            echo "</div>";
        }

        echo "<div class='col-md-6 sso-form-field'><label>" . __('SP certificate (optional)', 'sso') . "</label>";
        echo "<textarea name='sp_x509cert' rows='5' class='form-control font-monospace'>"
            . htmlspecialchars((string) $this->fields['sp_x509cert'], ENT_QUOTES, 'UTF-8') . "</textarea></div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('SP private key (optional)', 'sso') . "</label>";
        echo "<textarea name='sp_private_key' rows='5' class='form-control font-monospace' placeholder='"
            . (($this->fields['sp_private_key'] ?? '') !== '' ? __('(unchanged)', 'sso') : '-----BEGIN PRIVATE KEY-----')
            . "'></textarea></div>";
        self::closeFormCard();

        // ---------------- JIT / matching ----------------
        self::showFormSection(__('Provisioning and matching', 'sso'), 'ti ti-users-plus');

        self::openFormCard();
        echo "<div class='col-md-6 sso-form-field sso-field-compact'><label>"
            . __('Create unknown users (JIT)', 'sso') . "</label>"
            . "<div class='form-hint mb-2'>" . __('OFF: only pre-existing users can log in', 'sso') . "</div>";
        Dropdown::showYesNo('jit_create', (int) $this->fields['jit_create']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field sso-field-compact'><label>"
            . __('Update user fields on each login', 'sso') . "</label>";
        Dropdown::showYesNo('jit_update', (int) $this->fields['jit_update']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Match existing users by', 'sso') . "</label>";
        Dropdown::showFromArray('matching_field', [
            'email' => _n('Email', 'Emails', 1),
            'name'  => __('Login'),
        ], ['value' => $this->fields['matching_field']]);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Apply authorization rules', 'sso') . "</label>";
        Dropdown::showFromArray('rules_mode', [
            'always'         => __('On every login', 'sso'),
            'on_create_only' => __('Only when the user is created', 'sso'),
        ], ['value' => $this->fields['rules_mode']]);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Default profile (JIT)', 'sso') . "</label>";
        Dropdown::show('Profile', ['name' => 'default_profiles_id',
            'value' => (int) $this->fields['default_profiles_id']]);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Default entity (JIT)', 'sso') . "</label>";
        Entity::dropdown(['name' => 'default_entities_id',
            'value' => (int) $this->fields['default_entities_id'], 'entity' => -1]);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>" . __('Groups claim/attribute', 'sso') . "</label>";
        echo Html::input('groups_claim', ['value' => $this->fields['groups_claim'], 'class' => 'form-control']);
        echo "</div>";
        echo "<div class='col-md-6 sso-form-field'><label>"
            . __('Email domain allowlist (CSV, empty = all)', 'sso') . "</label>";
        echo Html::input('domain_allowlist', ['value' => $this->fields['domain_allowlist'], 'class' => 'form-control',
            'placeholder' => 'acme.com, filial.acme.com']);
        echo "</div>";
        echo "<div class='col-12 sso-form-field'><label>"
            . __('Claim mapping (JSON: GLPI field → claim)', 'sso') . "</label>";
        echo "<textarea name='claim_mapping' rows='4' class='form-control font-monospace'>"
            . htmlspecialchars((string) $this->fields['claim_mapping'], ENT_QUOTES, 'UTF-8') . "</textarea>";
        echo "</div>";
        self::closeFormCard();

        // ---------------- SCIM ----------------
        self::showFormSection(__('SCIM provisioning', 'sso'), 'ti ti-arrows-exchange');

        $scim_url = Config::baseUrl() . '/plugins/sso/front/scim.php/v2';
        self::openFormCard();
        echo "<div class='col-lg-3 sso-form-field sso-field-compact'>";
        echo "<label class='sso-setting-label'><i class='ti ti-arrows-exchange me-1'></i>"
            . __('Enable SCIM', 'sso') . "</label>";
        Dropdown::showYesNo('scim_enabled', (int) ($this->fields['scim_enabled'] ?? 0));
        echo "</div>";
        echo "<div class='col-lg-9 sso-form-field'>";
        echo "<label class='sso-setting-label' for='sso-scim-url'><i class='ti ti-link me-1'></i>"
            . __('SCIM base URL', 'sso') . "</label>";
        echo "<div class='sso-copy-field'>";
        echo "<code id='sso-scim-url'>" . htmlspecialchars($scim_url, ENT_QUOTES, 'UTF-8') . "</code>";
        echo "<button type='button' class='btn btn-outline-secondary sso-copy-button' data-copy-target='sso-scim-url'"
            . " title='" . htmlspecialchars(__('Copy URL', 'sso'), ENT_QUOTES, 'UTF-8') . "'>"
            . "<i class='ti ti-copy'></i><span>" . __('Copy', 'sso') . "</span></button>";
        echo "</div></div>";

        if ($ID > 0) {
            $has_token = trim((string) ($this->fields['scim_token_hash'] ?? '')) !== '';
            echo "<div class='col-12'><div class='sso-token-panel'>";
            echo "<div class='sso-token-info'><span class='sso-setting-label'><i class='ti ti-key me-1'></i>"
                . __('SCIM Bearer token', 'sso') . "</span><div class='sso-token-status'>";
            echo $has_token
                ? "<span class='badge bg-success-lt text-success'><i class='ti ti-circle-check me-1'></i>"
                    . __('Configured', 'sso') . "</span>"
                : "<span class='badge bg-secondary-lt text-secondary'><i class='ti ti-circle-minus me-1'></i>"
                    . __('Not configured', 'sso') . "</span>";
            echo "</div><div class='text-muted small mt-2'>"
                . __('The clear-text token is shown only once when generated.', 'sso') . "</div></div>";
            echo "<div class='sso-token-actions' style='margin-top:1.25rem'>";
            echo "<div class='sso-token-action'>";
            echo Html::submit(__('Generate new token', 'sso'), [
                'name' => 'generate_scim_token', 'class' => 'btn btn-outline-primary',
                'icon' => 'ti ti-refresh',
            ]);
            echo "</div>";
            if ($has_token) {
                echo "<div class='sso-token-action' style='margin-top:1rem'>";
                echo Html::submit(__('Revoke token', 'sso'), [
                    'name' => 'revoke_scim_token', 'class' => 'btn btn-outline-danger',
                    'icon' => 'ti ti-ban',
                ]);
                echo "</div>";
            }
            echo "</div></div></div>";
        }
        self::closeFormCard();

        // ---------------- UI ----------------
        self::showFormSection(__('Login page button', 'sso'), 'ti ti-login-2');

        $current_icon = trim((string) ($this->fields['icon'] ?? ''));
        if ($current_icon === '') {
            $current_icon = $proto === self::PROTO_OIDC ? 'ti ti-circle-key' : 'ti ti-certificate';
        }
        $icon_presets = [
            'ti ti-key'             => 'Keycloak',
            self::ICON_MICROSOFT    => 'Microsoft Entra',
            self::ICON_GOOGLE       => 'Google',
            'ti ti-circle-key'      => __('OpenID Connect', 'sso'),
            'ti ti-certificate'     => __('SAML 2.0', 'sso'),
            'ti ti-shield-lock'     => __('Secure provider', 'sso'),
            'ti ti-login'           => __('Generic', 'sso'),
        ];
        $button_name = trim((string) ($this->fields['button_label'] ?? ''));
        if ($button_name === '') {
            $button_name = trim((string) ($this->fields['name'] ?? ''));
        }
        if ($button_name === '') {
            $button_name = 'SSO';
        }
        $preview_label = sprintf(__('Log in with %s', 'sso'), $button_name);
        $login_presentation = in_array(
            (string) ($this->fields['login_presentation'] ?? 'button'),
            self::LOGIN_PRESENTATIONS,
            true
        ) ? (string) $this->fields['login_presentation'] : 'button';

        self::openFormCard();
        echo "<div class='col-md-4 sso-form-field sso-presentation-field'>";
        echo "<label class='sso-setting-label'><i class='ti ti-layout-grid me-1'></i>"
            . __('Display on login', 'sso') . "</label>";
        Dropdown::showFromArray('login_presentation', [
            'button' => __('Button', 'sso'),
            'icon'   => __('Icon only', 'sso'),
        ], [
            'value'     => $login_presentation,
            'on_change' => 'ssoUpdateLoginPresentation(this.value)',
        ]);
        echo "</div>";
        echo "<div class='col-md-8 sso-form-field'>";
        echo "<label class='sso-setting-label' for='sso-button-label'><i class='ti ti-letter-case me-1'></i>"
            . __('Button label', 'sso') . "</label>";
        echo Html::input('button_label', [
            'id' => 'sso-button-label', 'value' => $this->fields['button_label'],
            'class' => 'form-control', 'placeholder' => __('Uses the provider name when empty', 'sso'),
        ]);
        echo "</div>";
        echo "<div class='col-12 sso-form-field sso-preview-field'><div class='sso-preview-panel'>";
        echo "<span class='sso-setting-label'><i class='ti ti-eye me-1'></i>"
            . __('Login preview', 'sso') . "</span>";
        echo "<div class='sso-preview-control'><span id='sso-button-preview'"
            . " class='btn btn-primary sso-button-preview"
            . ($login_presentation === 'icon' ? " sso-button-preview--icon" : '')
            . "' aria-disabled='true' aria-label='"
            . htmlspecialchars($preview_label, ENT_QUOTES, 'UTF-8') . "' title='"
            . htmlspecialchars($preview_label, ENT_QUOTES, 'UTF-8') . "'>"
            . "<span id='sso-button-preview-icon'>" . self::renderProviderIcon($current_icon) . "</span>"
            . "<span class='sso-button-preview-label'>" . htmlspecialchars($preview_label, ENT_QUOTES, 'UTF-8')
            . "</span></span></div></div></div>";

        echo "<div class='col-12 sso-form-field sso-icon-picker'>";
        echo "<label class='sso-setting-label' for='sso-icon-select'><i class='ti ti-icons me-1'></i>"
            . __('Choose an icon', 'sso') . "</label>";
        echo "<div class='sso-icon-combobox'>";
        echo "<select id='sso-icon-select' name='icon' class='form-select' data-custom-label='"
            . htmlspecialchars(__('Custom: %s', 'sso'), ENT_QUOTES, 'UTF-8') . "'>";
        foreach ($icon_presets as $icon_class => $icon_label) {
            $selected = $current_icon === $icon_class;
            $asset_url = self::brandIconUrl($icon_class);
            echo "<option value='" . htmlspecialchars($icon_class, ENT_QUOTES, 'UTF-8') . "'"
                . " data-icon='" . htmlspecialchars($icon_class, ENT_QUOTES, 'UTF-8') . "'"
                . ($asset_url !== null ? " data-icon-src='"
                    . htmlspecialchars($asset_url, ENT_QUOTES, 'UTF-8') . "'" : '')
                . ($selected ? ' selected' : '') . ">"
                . htmlspecialchars($icon_label, ENT_QUOTES, 'UTF-8') . "</option>";
        }
        if (!array_key_exists($current_icon, $icon_presets)) {
            echo "<option value='" . htmlspecialchars($current_icon, ENT_QUOTES, 'UTF-8') . "'"
                . " data-icon='" . htmlspecialchars($current_icon, ENT_QUOTES, 'UTF-8') . "' data-custom='1' selected>"
                . htmlspecialchars(sprintf(__('Custom: %s', 'sso'), $current_icon), ENT_QUOTES, 'UTF-8') . "</option>";
        }
        echo "</select></div></div>";
        echo "<div class='col-12 sso-form-field sso-advanced-field'>";
        echo "<details class='sso-icon-advanced'" . (!array_key_exists($current_icon, $icon_presets) ? ' open' : '') . ">";
        echo "<summary><i class='ti ti-adjustments me-1'></i>" . __('Custom Tabler class', 'sso') . "</summary>";
        echo "<div class='input-group mt-2'>"
            . "<span id='sso-custom-icon-preview' class='input-group-text'>"
            . self::renderProviderIcon($current_icon) . "</span>"
            . "<input type='text' id='sso-icon-custom' class='form-control font-monospace' value='"
            . htmlspecialchars($current_icon, ENT_QUOTES, 'UTF-8') . "' placeholder='ti ti-login'>"
            . "</div><div class='form-hint'>" . __('Only use this if none of the presets fits.', 'sso') . "</div>";
        echo "</details></div>";

        echo "<div class='col-12 sso-form-field'>";
        echo "<label class='sso-setting-label' for='sso-idp-comment'><i class='ti ti-message me-1'></i>"
            . __('Comments') . "</label>";
        echo "<textarea id='sso-idp-comment' name='comment' rows='2' class='form-control'>"
            . htmlspecialchars((string) $this->fields['comment'], ENT_QUOTES, 'UTF-8') . "</textarea>";
        echo "</div>";
        self::closeFormCard();

        echo Html::scriptBlock("
            var ssoFormMarker = document.getElementById('sso-idp-form-marker');
            if (ssoFormMarker && ssoFormMarker.closest('table')) {
                ssoFormMarker.closest('table').classList.add('sso-idp-form');
            }
            function ssoToggleProtocol(proto, chooseDefaultIcon) {
                document.querySelectorAll('.sso-proto').forEach(function (row) {
                    row.style.display = row.classList.contains('sso-proto-' + proto) ? '' : 'none';
                });
                var iconSelect = document.getElementById('sso-icon-select');
                if (chooseDefaultIcon && iconSelect && [
                    'ti ti-login', 'ti ti-certificate', 'ti ti-circle-key'
                ].includes(iconSelect.value)) {
                    ssoSelectIcon(proto === 'oidc' ? 'ti ti-circle-key' : 'ti ti-certificate');
                }
            }
            function ssoFormatIconOption(option) {
                if (!option.id || !option.element) return option.text;
                var content = document.createElement('span');
                content.className = 'sso-icon-option-content';
                var label = document.createElement('span');
                label.textContent = option.text;
                content.appendChild(ssoBuildIcon(
                    option.element.dataset.icon || option.id,
                    option.element.dataset.iconSrc || ''
                ));
                content.appendChild(label);
                return window.jQuery ? window.jQuery(content) : content;
            }
            function ssoBuildIcon(iconClass, assetUrl) {
                if (assetUrl) {
                    var frame = document.createElement('span');
                    frame.className = 'sso-brand-icon-frame';
                    var image = document.createElement('img');
                    image.className = 'sso-brand-icon';
                    image.src = assetUrl;
                    image.alt = '';
                    image.width = 18;
                    image.height = 18;
                    frame.appendChild(image);
                    return frame;
                }
                var icon = document.createElement('i');
                icon.className = iconClass;
                icon.setAttribute('aria-hidden', 'true');
                return icon;
            }
            function ssoRenderIcon(host, iconClass, assetUrl) {
                if (!host) return;
                host.replaceChildren(ssoBuildIcon(iconClass, assetUrl));
            }
            var ssoIconSelect = document.getElementById('sso-icon-select');
            if (ssoIconSelect && window.jQuery && window.jQuery.fn.select2) {
                window.jQuery(ssoIconSelect).select2({
                    width: '100%',
                    minimumResultsForSearch: Infinity,
                    templateResult: ssoFormatIconOption,
                    templateSelection: ssoFormatIconOption
                });
            }
            function ssoSelectIcon(iconClass, syncSelect) {
                var custom = document.getElementById('sso-icon-custom');
                var customPreview = document.getElementById('sso-custom-icon-preview');
                var buttonPreview = document.getElementById('sso-button-preview-icon');
                var matchingOption = null;
                if (syncSelect !== false && ssoIconSelect) {
                    matchingOption = Array.from(ssoIconSelect.options).find(function (option) {
                        return option.value === iconClass;
                    });
                    if (!matchingOption) {
                        Array.from(ssoIconSelect.querySelectorAll('option[data-custom]')).forEach(function (option) {
                            option.remove();
                        });
                        matchingOption = new Option(
                            ssoIconSelect.dataset.customLabel.replace('%s', iconClass),
                            iconClass,
                            true,
                            true
                        );
                        matchingOption.dataset.icon = iconClass;
                        matchingOption.dataset.custom = '1';
                        ssoIconSelect.add(matchingOption);
                    }
                    ssoIconSelect.value = iconClass;
                    if (window.jQuery && window.jQuery.fn.select2) {
                        window.jQuery(ssoIconSelect).trigger('change.select2');
                    }
                }
                if (!matchingOption && ssoIconSelect) {
                    matchingOption = Array.from(ssoIconSelect.options).find(function (option) {
                        return option.value === iconClass;
                    });
                }
                var assetUrl = matchingOption ? (matchingOption.dataset.iconSrc || '') : '';
                if (custom && custom.value !== iconClass) custom.value = iconClass;
                ssoRenderIcon(customPreview, iconClass, assetUrl);
                ssoRenderIcon(buttonPreview, iconClass, assetUrl);
            }
            if (ssoIconSelect) {
                var ssoIconChangeHandler = function () {
                    ssoSelectIcon(ssoIconSelect.value, false);
                };
                if (window.jQuery) {
                    window.jQuery(ssoIconSelect).on('change.ssoIcon', ssoIconChangeHandler);
                } else {
                    ssoIconSelect.addEventListener('change', ssoIconChangeHandler);
                }
            }
            var customIcon = document.getElementById('sso-icon-custom');
            if (customIcon) {
                customIcon.addEventListener('input', function () { ssoSelectIcon(customIcon.value.trim()); });
            }
            var labelInput = document.querySelector('[name=button_label]');
            var nameInput = document.querySelector('[name=name]');
            var presentationSelect = document.querySelector('[name=login_presentation]');
            function ssoUpdateLoginPresentation(value) {
                var preview = document.getElementById('sso-button-preview');
                if (!preview) return;
                preview.classList.toggle('sso-button-preview--icon', value === 'icon');
            }
            function ssoUpdateButtonPreview() {
                var label = labelInput && labelInput.value.trim() !== ''
                    ? labelInput.value.trim()
                    : (nameInput && nameInput.value.trim() !== '' ? nameInput.value.trim() : 'SSO');
                var preview = document.querySelector('#sso-button-preview .sso-button-preview-label');
                var previewHost = document.getElementById('sso-button-preview');
                var fullLabel = " . json_encode(__('Log in with %s', 'sso')) . ".replace('%s', label);
                if (preview) preview.textContent = fullLabel;
                if (previewHost) {
                    previewHost.setAttribute('aria-label', fullLabel);
                    previewHost.setAttribute('title', fullLabel);
                }
            }
            if (labelInput) labelInput.addEventListener('input', ssoUpdateButtonPreview);
            if (nameInput) nameInput.addEventListener('input', ssoUpdateButtonPreview);
            if (presentationSelect) {
                presentationSelect.addEventListener('change', function () {
                    ssoUpdateLoginPresentation(presentationSelect.value);
                });
                ssoUpdateLoginPresentation(presentationSelect.value);
            }
            document.querySelectorAll('[data-copy-target]').forEach(function (button) {
                button.addEventListener('click', function () {
                    var target = document.getElementById(button.dataset.copyTarget);
                    if (!target) return;
                    var copyText = function (content) {
                        if (navigator.clipboard && window.isSecureContext) {
                            return navigator.clipboard.writeText(content);
                        }
                        var temporary = document.createElement('textarea');
                        temporary.value = content;
                        temporary.setAttribute('readonly', '');
                        temporary.style.position = 'fixed';
                        temporary.style.opacity = '0';
                        document.body.appendChild(temporary);
                        temporary.select();
                        document.execCommand('copy');
                        temporary.remove();
                        return Promise.resolve();
                    };
                    copyText(target.textContent).then(function () {
                        var text = button.querySelector('span');
                        var previous = text ? text.textContent : '';
                        if (text) text.textContent = " . json_encode(__('Copied', 'sso')) . ";
                        button.classList.add('is-copied');
                        window.setTimeout(function () {
                            if (text) text.textContent = previous;
                            button.classList.remove('is-copied');
                        }, 1600);
                    });
                });
            });
            ssoToggleProtocol(" . json_encode($proto) . ", false);
        ");

        $this->showFormButtons($options);
        return true;
    }
}

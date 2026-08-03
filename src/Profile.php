<?php

namespace GlpiPlugin\Sso;

use CommonGLPI;
use Html;
use Profile as GlpiProfile;
use ProfileRight;
use Session;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

class Profile extends GlpiProfile
{
    public const RIGHT = 'plugin_sso';

    public static function getTypeName($nb = 0): string
    {
        return __('SSO', 'sso');
    }

    /** Crea el right con valor 0 en todos los perfiles si no existe. */
    public static function initProfile(): void
    {
        global $DB;

        $right = new ProfileRight();
        foreach ($DB->request(['SELECT' => 'id', 'FROM' => 'glpi_profiles']) as $profile) {
            $exists = countElementsInTable('glpi_profilerights', [
                'profiles_id' => $profile['id'],
                'name'        => self::RIGHT,
            ]);
            if ($exists === 0) {
                $right->add([
                    'profiles_id' => $profile['id'],
                    'name'        => self::RIGHT,
                    'rights'      => 0,
                ]);
            }
        }
    }

    /** Da acceso total (READ|UPDATE|CREATE|PURGE) al perfil que instala. */
    public static function createFirstAccess(int $profiles_id): void
    {
        ProfileRight::updateProfileRights($profiles_id, [
            self::RIGHT => ALLSTANDARDRIGHT,
        ]);
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof GlpiProfile && $item->getField('id')) {
            return self::getTypeName();
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof GlpiProfile && $item->getField('id')) {
            $prof = new self();
            $prof->showForm((int) $item->getField('id'));
        }
        return true;
    }

    public function showForm($profiles_id = 0, $options = [])
    {
        echo "<div class='spaced'>";
        $profile = new GlpiProfile();
        $profile->getFromDB($profiles_id);

        $rights = [[
            'itemtype' => self::class,
            'label'    => self::getTypeName(),
            'field'    => self::RIGHT,
        ]];

        $matrix_options = [
            'canedit'       => Session::haveRight('profile', UPDATE),
            'default_class' => 'tab_bg_2',
            'title'         => self::getTypeName(),
        ];

        echo "<form method='post' action='" . $profile->getFormURL() . "'>";
        $profile->displayRightsChoiceMatrix($rights, $matrix_options);
        if ($matrix_options['canedit']) {
            echo "<div class='center'>";
            echo Html::hidden('id', ['value' => $profiles_id]);
            echo Html::submit(_sx('button', 'Save'), ['name' => 'update', 'class' => 'btn btn-primary']);
            echo "</div>";
        }
        Html::closeForm();
        echo "</div>";
        return true;
    }
}

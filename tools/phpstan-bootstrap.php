<?php

/**
 * Constantes que GLPI define en runtime, para el análisis estático.
 * Sólo símbolos: acá no se ejecuta nada de GLPI.
 */
foreach ([
    'GLPI_ROOT'            => '/var/www/glpi',
    'GLPI_VERSION'         => '11.0.8',
    'GLPI_DOC_DIR'         => '/var/glpi/files',
    'MINUTE_TIMESTAMP'     => 60,
    'HOUR_TIMESTAMP'       => 3600,
    'DAY_TIMESTAMP'        => 86400,
    'WEEK_TIMESTAMP'       => 604800,
    'MONTH_TIMESTAMP'      => 2592000,
    'READ'                 => 1,
    'UPDATE'               => 2,
    'CREATE'               => 4,
    'DELETE'               => 8,
    'PURGE'                => 16,
    'ALLSTANDARDRIGHT'     => 31,
    'INFO'                 => 0,
    'WARNING'              => 1,
    'ERROR'                => 2,
    'PLUGIN_SSO_VERSION'   => '1.0.0',
    'PLUGIN_SSO_MIN_GLPI'  => '11.0.0',
    'PLUGIN_SSO_MAX_GLPI'  => '11.9.99',
] as $name => $value) {
    if (!defined($name)) {
        define($name, $value);
    }
}

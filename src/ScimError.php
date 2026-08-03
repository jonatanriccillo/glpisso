<?php

namespace GlpiPlugin\Sso;

use RuntimeException;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/** Error SCIM: status HTTP + scimType del spec. */
final class ScimError extends RuntimeException
{
    public function __construct(
        public readonly int $status,
        string $message,
        public readonly string $scim_type = ''
    ) {
        parent::__construct($message);
    }
}

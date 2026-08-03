<?php
/** SCIM 2.0 stateless endpoint (Bearer por IdP). */

use GlpiPlugin\Sso\ScimServer;

include('../../../inc/includes.php');

ScimServer::run();

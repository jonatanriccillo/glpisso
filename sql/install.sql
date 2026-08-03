-- SSO 0.2.0 — esquema acumulativo. Ver BLUEPRINT §4.
-- Regla de la casa: toda tabla que crece sola tiene índice para su patrón de
-- consulta y purga automática por cron (lección glpisaml/loginstates).

CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_idps` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(255) NOT NULL DEFAULT '',
    `is_active` TINYINT NOT NULL DEFAULT 0,
    `is_deleted` TINYINT NOT NULL DEFAULT 0,
    `ranking` INT NOT NULL DEFAULT 0,
    `protocol` VARCHAR(10) NOT NULL DEFAULT 'saml',
    -- OIDC
    `issuer_url` VARCHAR(255) NOT NULL DEFAULT '',
    `client_id` VARCHAR(255) NOT NULL DEFAULT '',
    `client_secret` TEXT,
    `scopes` VARCHAR(255) NOT NULL DEFAULT 'openid profile email',
    `require_email_verified` TINYINT NOT NULL DEFAULT 1,
    `discovery_cache` TEXT,
    `discovery_cached_at` TIMESTAMP NULL DEFAULT NULL,
    `jwks_cache` TEXT,
    `jwks_cached_at` TIMESTAMP NULL DEFAULT NULL,
    -- SAML
    `idp_entity_id` VARCHAR(255) NOT NULL DEFAULT '',
    `idp_sso_url` VARCHAR(255) NOT NULL DEFAULT '',
    `idp_slo_url` VARCHAR(255) NOT NULL DEFAULT '',
    `idp_x509cert` TEXT,
    `idp_x509cert_rollover` TEXT,
    `nameid_format` VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    `sign_authn_requests` TINYINT NOT NULL DEFAULT 0,
    `want_assertions_encrypted` TINYINT NOT NULL DEFAULT 0,
    `sp_private_key` TEXT,
    `sp_x509cert` TEXT,
    -- JIT / matching
    `jit_create` TINYINT NOT NULL DEFAULT 0,
    `jit_update` TINYINT NOT NULL DEFAULT 0,
    `matching_field` VARCHAR(20) NOT NULL DEFAULT 'email',
    `default_profiles_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `default_entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `claim_mapping` TEXT,
    `groups_claim` VARCHAR(100) NOT NULL DEFAULT 'groups',
    `rules_mode` VARCHAR(20) NOT NULL DEFAULT 'always',
    `domain_allowlist` VARCHAR(255) NOT NULL DEFAULT '',
    -- SCIM (M6)
    `scim_enabled` TINYINT NOT NULL DEFAULT 0,
    `scim_token_hash` VARCHAR(64) NOT NULL DEFAULT '',
    -- UI
    `login_presentation` VARCHAR(20) NOT NULL DEFAULT 'button',
    `button_label` VARCHAR(255) NOT NULL DEFAULT '',
    `icon` VARCHAR(100) NOT NULL DEFAULT 'ti ti-login',
    `comment` TEXT,
    `date_creation` TIMESTAMP NULL DEFAULT NULL,
    `date_mod` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `name` (`name`),
    KEY `is_active` (`is_active`, `ranking`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- Estado de flujo pendiente: state OIDC / AuthnRequest SAML / replay cache /
-- tickets one-shot de finalización de login. TTL corto SIEMPRE.
CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_requeststates` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `idps_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `kind` VARCHAR(20) NOT NULL DEFAULT '',
    `token` VARCHAR(191) NOT NULL DEFAULT '',
    `payload` TEXT,
    `expires_at` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `unicity` (`kind`, `token`),
    KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- Identidad estable: (IdP, subject) ↔ usuario GLPI. Sobrevive cambios de email.
CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_userlinks` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `idps_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `subject` VARCHAR(191) NOT NULL DEFAULT '',
    `date_creation` TIMESTAMP NULL DEFAULT NULL,
    `last_login` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `unicity` (`idps_id`, `subject`),
    KEY `users_id` (`users_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- M6: ownership de grupos SCIM. El grupo core queda dedicado a un único IdP;
-- esta relación impide que el Bearer de un IdP vea o modifique grupos ajenos.
CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_scimgroups` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `idps_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `groups_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `external_id` VARCHAR(191) NOT NULL DEFAULT '',
    `date_creation` TIMESTAMP NULL DEFAULT NULL,
    `date_mod` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idp_external` (`idps_id`, `external_id`),
    UNIQUE KEY `groups_id` (`groups_id`),
    KEY `idps_id` (`idps_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- Auditoría de eventos de auth. Purga por retención (cron purgelogs).
CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_logs` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `date` TIMESTAMP NULL DEFAULT NULL,
    `idps_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `event` VARCHAR(50) NOT NULL DEFAULT '',
    `level` VARCHAR(10) NOT NULL DEFAULT 'info',
    `ip` VARCHAR(45) NOT NULL DEFAULT '',
    `message` VARCHAR(255) NOT NULL DEFAULT '',
    `details` TEXT,
    PRIMARY KEY (`id`),
    KEY `date` (`date`),
    KEY `idp_date` (`idps_id`, `date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- Asignación del right plugin_sso (patrón de la casa).
CREATE TABLE IF NOT EXISTS `glpi_plugin_sso_profiles` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `profiles_id` INT UNSIGNED NOT NULL DEFAULT 0,
    `rights` INT NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    UNIQUE KEY `profiles_id` (`profiles_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

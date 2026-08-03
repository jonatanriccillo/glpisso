# Changelog

## [1.0.1]

### Corregido
- El aterrizaje posterior al login usa una página con redirección
  JavaScript en lugar de un 302: la cookie de sesión de GLPI
  (`SameSite=Strict`) se perdía en la cadena de redirecciones proveniente
  del proveedor de identidad y el usuario volvía a la pantalla de login a
  pesar de haberse autenticado correctamente.
- Los campos del proveedor (client ID, issuer, URLs de SSO/SLO,
  certificados, dominios) se guardan sin espacios ni saltos de línea
  accidentales. Un espacio arrastrado al copiar el client ID producía un
  `401 invalid_client` sin ninguna pista de la causa.

## [1.0.0]

Primera versión.

### Autenticación
- Login SAML 2.0 (SP-initiated, POST binding) y OpenID Connect
  (Authorization Code + PKCE S256) con multi-IdP.
- Validación completa del id_token: whitelist de algoritmos (jamás
  `none`/HS*), firma contra JWKS con refetch ante rotación de claves,
  `iss` exacto, `aud`/`azp`, `exp`/`iat` con skew, `nonce` fail-closed.
- Estado de flujo en DB con TTL y purga (no en sesión PHP): el ACS
  cross-site funciona con `SameSite=Lax` y no crea sesión — emite un
  ticket one-shot que canjea `finish.php`.
- Single Logout en ambos protocolos; forced SSO con bypass `?noSSO=1`;
  anti open-redirect estricto.
- Guards de método HTTP en los 7 endpoints públicos.

### Identidad y autorización
- Link persistente (IdP, subject) → usuario GLPI: sobrevive cambios de
  email. Adopción de usuarios preexistentes configurable.
- JIT provisioning opcional (OFF por defecto) acotado por allowlist de
  dominios; `email_verified` exigido en OIDC (apagable por IdP).
- Motor de reglas nativo (`RuleAuth` sobre el engine de GLPI): criterios
  AND/OR, deny, perfil/entidad/grupos por regla, UI estándar completa.

### Provisioning SCIM 2.0
- Servidor por IdP (`/plugins/sso/front/scim.php/v2`): discovery, Users
  y Groups con CRUD/PUT/PATCH, paginado, filtros; Bearer por IdP (sólo
  se persiste SHA-256, con rotación/revocación).
- Baja lógica con invalidación de sesiones vivas; ownership de grupos
  con aislamiento fail-closed entre IdPs.

### Operación
- `php bin/console plugins:sso:doctor` + vista admin + support bundle
  JSON redactado por construcción; exit code apto para monitoreo.
- CertWatch: cron diario + banner cuando un certificado vence en <30 días.
- Crons de purga (estado de flujo y logs) en `MODE_EXTERNAL`.
- Secretos cifrados con GLPIKey y registrados en `secured_fields`:
  `glpi:security:change_key` los re-cifra (verificado con doble rotación).
- Logs de auth consultables (evento, nivel, IdP, usuario) con retención.

### Calidad
- Suite de 38 tests PHP puros (matriz de ataques como regresión), CI de
  GitHub Actions, vendor con checksums verificables, script de paquete
  con SHA-256 y QA de ciclo de vida install/upgrade/uninstall en
  instancia descartable.
- Docs: README, INSTALL (guías Keycloak/Entra/Google), MIGRATION
  (runbook desde glpisaml), OPERATIONS (runbook de operación), UPGRADE,
  VENDOR.

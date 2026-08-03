# Operación — plugin SSO

Runbook para quien opera el plugin en producción. Complementa
`INSTALL.md` (alta inicial) y `MIGRATION.md` (migración desde glpisaml).

## Diagnóstico

- **CLI**: `php bin/console plugins:sso:doctor` — DB, crons, config e
  IdPs (con probes HTTP a discovery/JWKS; `--no-network` para omitirlos).
  Exit code 1 si hay fallas → usable como check de monitoreo.
- **Web**: `/plugins/sso/front/doctor.php` (requiere el derecho
  `plugin_sso`). Mismo contenido + descarga del support bundle.
- **Support bundle**: `plugins:sso:doctor --bundle` o el botón de la
  página. JSON **redactado por construcción**: versiones, chequeos,
  fingerprints/vencimientos de certificados y últimos 20 eventos (sólo
  evento/nivel/fecha/IdP). Nunca incluye secretos, tokens, assertions,
  session IDs, mensajes de log ni IPs. Apto para adjuntar a un ticket.

## Backup / restore

Las 6 tablas del plugin (`glpi_plugin_sso_*`) viajan con el dump normal
de la DB de GLPI — no hay estado fuera de la DB. Restore = restaurar el
dump + volver a desplegar la carpeta del plugin en la misma versión
(`glpi_plugins.version` debe coincidir con `setup.php`; si difiere,
`plugin:install --force` + `plugin:activate`).

**Ojo con GLPIKey**: los secretos de IdP están cifrados con la clave de
`config/glpicrypt.key`. Un restore de DB en una instancia con OTRA clave
deja los secretos indescifrables → backupear esa clave junto con la DB, o
recargar los secretos a mano tras el restore.

## Rotación de secretos y claves

- **GLPIKey** (`php bin/console glpi:security:change_key`): soportado —
  el hook `secured_fields` re-cifra `client_secret`/`sp_private_key`
  automáticamente (verificado con rotación doble + login E2E). Correr el
  doctor después para confirmar.
- **client_secret OIDC**: generar el nuevo en el IdP, pegarlo en el form
  del IdP en GLPI (campo vacío = conserva el actual), probar login.
  Coordinar con la ventana de validez del IdP (Keycloak/Entra permiten
  dos secretos vigentes en paralelo).
- **Certificado SAML del IdP**: `certwatch` avisa 30 días antes (log +
  banner en el form del IdP). Actualizar el cert en la fila del IdP
  cuando el IdP publique el nuevo (o re-importar metadata).
- **Bearer SCIM**: botón de rotar en el form del IdP; el token se muestra
  UNA vez. Actualizarlo inmediatamente en el cliente SCIM.

## Alta / baja de IdP

- Alta: form de IdP (importar metadata SAML o discovery OIDC), probar
  con un usuario de prueba ANTES de activar forced SSO.
- Baja: desactivar el IdP (no borrar) → conserva userlinks y auditoría.
  Borrarlo elimina sus links; los usuarios GLPI quedan (huérfanos de
  link, pueden re-vincularse por matching en el próximo login si otro
  IdP los cubre).

## Incidentes

| Síntoma | Acción |
|---|---|
| IdP caído / discovery no responde | Los usuarios locales entran con `?noSSO=1` (bypass del forced SSO). El doctor muestra el probe en FAIL. Esperar al IdP o desactivar forced SSO temporalmente. |
| "Authentication failed" genérico en login | Revisar los últimos eventos `error_*` en la pestaña de logs del plugin o `glpi_plugin_sso_logs`; el mensaje al usuario es neutro a propósito. |
| Secretos indescifrables tras mover la instancia | Se restauró DB sin `glpicrypt.key`. Recargar client_secret/sp_private_key a mano. |
| Lockeo total (nadie entra) | `?noSSO=1` con una cuenta local. Si el plugin rompe el login page: `php bin/console plugin:deactivate sso` (no borra datos). |
| Cert SAML vencido | El login SAML falla en la validación de firma. Actualizar el cert del IdP en la fila del IdP; `certwatch` debería haber avisado antes. |

## Actualización del plugin

Ver `UPGRADE.md`. Regla corta: backup DB → reemplazar carpeta →
`plugin:install --force` + `plugin:activate` (idempotente, los datos
sobreviven — verificado en QA de ciclo de vida) → `plugins:sso:doctor`.
Rollback: restaurar la carpeta de la versión anterior + `--force` +
activate (el esquema es aditivo; las columnas nuevas no molestan).

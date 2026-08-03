# Actualización segura del plugin SSO

Este procedimiento actualiza el código y el esquema **sin borrar la
configuración, IdPs, vínculos, logs ni reglas**. Aplica a upgrades soportados
dentro de GLPI 11, incluido `sso 0.1.x → 0.2.x`.

> **Nunca usar Desinstalar / `plugin:uninstall sso` para actualizar.** El
> uninstall es deliberadamente destructivo: elimina las tablas propias y las
> reglas del plugin. El comando correcto es `plugin:install --force sso`, que
> GLPI usa también para ejecutar el hook de actualización.

## Cómo protege los datos el código

`plugin_sso_install()` separa dos casos:

1. Si no existe `glpi_plugin_sso_idps`, ejecuta una instalación limpia.
2. Si la tabla ya existe, llama a `plugin_sso_migrate()`.

La migración consulta `fieldExists()` antes de agregar columnas, usa
`Migration::addField()` y luego reejecuta `sql/install.sql`, donde todas las
tablas se crean con `CREATE TABLE IF NOT EXISTS`. No hay `DROP`, `TRUNCATE` ni
recreación de tablas durante install/update. El upgrade 0.1→0.2 ya fue probado
en el lab eliminando las columnas SCIM, ejecutando `plugin:install --force` y
verificando que reaparecieron con sus defaults sin alterar los IdPs.

## 1. Preflight obligatorio

1. Leer release notes y confirmar compatibilidad con la versión GLPI/PHP/DB.
2. Programar ventana o drenar tráfico para no mezclar procesos con código
   viejo y nuevo.
3. Guardar el artefacto exacto de la versión instalada y el nuevo, ambos con
   SHA-256.
4. Hacer backup consistente de **toda la base GLPI**, no sólo de las tablas
   del plugin. Ejemplo genérico:

   ```bash
   mysqldump --single-transaction --routines --triggers <database> \
     > glpi-before-sso-update.sql
   ```

5. Guardar una copia del directorio actual `plugins/sso/` y registrar:

   ```bash
   php bin/console plugin:list
   php bin/console system:status
   ```

6. Registrar baseline de datos:

   ```sql
   SELECT id, name, protocol, is_active
     FROM glpi_plugin_sso_idps ORDER BY id;
   SELECT COUNT(*) FROM glpi_plugin_sso_userlinks;
   SELECT COUNT(*) FROM glpi_plugin_sso_logs;
   SELECT COUNT(*) FROM glpi_rules
    WHERE sub_type IN ('GlpiPlugin\\Sso\\RuleAuth', 'PluginSsoRuleAuth');
   ```

El dump debe validarse (`gzip -t`, restore de prueba o herramienta equivalente)
y almacenarse fuera del container que será reemplazado.

## 2. Actualización

1. Desactivar temporalmente el plugin o poner GLPI detrás de una ventana de
   mantenimiento. El login local/break-glass debe estar probado antes:

   ```bash
   php bin/console plugin:deactivate sso
   ```

2. Reemplazar `plugins/sso/` por el artefacto completo de la nueva versión.
   No copiar archivos sueltos desde un working tree ni conservar archivos
   obsoletos de una release anterior.
3. Desde la raíz de GLPI ejecutar:

   ```bash
   php bin/console plugin:install --force sso
   php bin/console plugin:activate sso
   php bin/console plugin:list
   php bin/console system:status
   ```

`plugin:install --force` debe terminar correctamente antes de activar. Si
falla, no desinstalar ni repetir operaciones destructivas: conservar salida,
logs y backup para diagnosticar.

## 3. Validación post-update

- `sso` aparece con la versión esperada y estado `Enabled`.
- `system:status` informa GLPI/DB/crons/filesystem en `OK`.
- Los IdPs conservan IDs, protocolo, estado, claims, certificados y secretos.
- Los conteos de `userlinks` y reglas coinciden con el baseline; un cambio en
  logs puede ser normal por las pruebas.
- Las tablas/columnas nuevas existen y una segunda ejecución de
  `plugin:install --force sso` no cambia datos ni falla.
- Probar una cuenta break-glass local y, por cada protocolo activo: login,
  autorización, logout; SCIM Test Connection/provisioning si se usa.
- Revisar logs del plugin/PHP y ejecutar `php bin/console plugins:sso:doctor`.

Mantener la ventana abierta hasta completar estas verificaciones.

## 4. Rollback

### Rollback de código

Es válido cuando la release declara sus migraciones como aditivas y
backward-compatible. Restaurar el directorio anterior, ejecutar
`plugin:install --force sso`, activar y repetir las validaciones. El upgrade
0.1→0.2 agrega columnas/tablas que 0.1 ignora, por lo que permite este rollback.

### Rollback de base

Si una release futura transforma/elimina datos o el update alcanzó a escribir
datos incompatibles, restaurar **código y dump de DB del mismo punto temporal**.
No mezclar DB restaurada con una versión distinta del código. El restore debe
seguir el procedimiento general de recuperación de GLPI y validarse antes de
reabrir tráfico.

En ambos casos `?noSSO=1` y una cuenta local permiten recuperar acceso sin
desinstalar el plugin.

## Política para migraciones futuras

- Cada versión soportada tiene camino de upgrade explícito y testeado.
- Migraciones idempotentes: `tableExists`/`fieldExists`/`indexExists` antes de
  crear; nunca asumir que una ejecución anterior terminó completa.
- Dentro de releases menores se prefieren cambios aditivos y defaults seguros.
- Ningún `DROP`, rename destructivo o backfill irreversible entra sin backup,
  versión intermedia, dry-run, verificación post-migración y rollback probado.
- CI debe cubrir clean install, upgrades desde cada versión mínima soportada,
  segunda ejecución idempotente y uninstall sólo en una DB descartable.
- El artefacto de release, hash, schema esperado y evidencia de migración se
  conservan junto al release.

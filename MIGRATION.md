# Runbook: migración desde `glpisaml`

Contexto: `glpisaml` es un plugin de terceros para login SAML en GLPI que no
tiene versión compatible con GLPI 11 — es un bloqueante habitual al migrar
de GLPI 10 a 11 para instancias que dependen de él. Este documento es el
runbook para reemplazarlo por `sso` sin dejar a nadie sin poder loguear.

**Antes de ejecutar esto en producción**: confirmar contra qué IdP federa tu
instancia actualmente (entity ID, endpoints SSO/SLO, certificados) leyendo
la configuración de `glpisaml`. Este runbook asume SAML genérico; ajustar
según tu IdP real.

---

## Por qué esto es seguro para los usuarios existentes

Los usuarios de prod **ya existen** en la tabla `glpi_users` de GLPI (los
creó `glpisaml`, LDAP, o el alta manual a lo largo del tiempo). El plugin
`sso` está diseñado explícitamente para esto:

- **`adopt_existing` (default ON)**: cuando alguien loguea por primera vez
  con `sso` y su email/login matchea un usuario preexistente, el plugin
  **vincula** esa cuenta (crea el link `(idp, subject)`) en vez de crear
  una duplicada. El `authtype` pasa a `EXTERNAL`.
- **JIT OFF por default**: si por algún motivo alguien loguea con un
  usuario que `glpisaml` nunca creó, `sso` **no** lo crea automáticamente
  salvo que lo actives a propósito — se cae al form local o queda
  denegado, nunca crea cuentas fantasma en silencio.

La migración es, en esencia: apagar `glpisaml`, prender `sso` apuntando al
mismo IdP, y verificar que el primer login de cada usuario dispare
adopción (no creación).

---

## Paso 1 — Inventario de la config actual de `glpisaml`

Antes de tocar nada, documentar (no hay export automático — es lectura
manual de la config de `glpisaml` en prod):

- [ ] URL del IdP (SSO/SLO), Entity ID del IdP, certificado(s) X.509.
- [ ] Entity ID / ACS que `glpisaml` tenía registrado en el IdP.
- [ ] Mapeo de atributos (qué atributo SAML mapeaba a qué campo de
      `glpi_users` — típicamente `name`/login, email, nombre, apellido).
- [ ] Reglas de asignación de perfil/entidad que tuviera `glpisaml`
      (su motor de reglas propio, si lo usaba) — van a rehacerse como
      **reglas del motor nativo** en `sso` (Administración > Reglas), no
      hay import automático entre ambos formatos.
- [ ] Confirmar el **formato del campo `name`** que dejó `glpisaml` en los
      usuarios existentes (¿login corto? ¿email completo?) — define qué
      `matching_field` usar en el IdP de `sso` (`email` vs `name`) para que
      el matching pegue.
- [ ] `SELECT COUNT(*) FROM glpi_users WHERE authtype = <el que use
      glpisaml>` — para tener un número de referencia y comparar
      post-migración.

## Paso 2 — Instalar `sso` en paralelo, sin activar el IdP todavía

1. Instalar y activar el plugin `sso` (ver [INSTALL.md](INSTALL.md)).
2. Dar de alta el IdP con **`is_active = 0`** (o simplemente no clickear
   "Activo" en el form): configuralo completo, probalo con un usuario de
   prueba (no productivo) usando la URL directa
   `front/login.php?idp=N`, que funciona **aunque el botón no esté
   visible** en el login mientras el IdP esté inactivo.
3. Verificar en **Configuración > SSO > Registro** que ese login de prueba
   dio `login_ok` (o `user_adopted` si matcheó un usuario real — usar un
   usuario de prueba dedicado, no uno productivo, para este paso).

## Paso 3 — Reglas de autorización

Recrear en **Administración > Reglas > Reglas de autorización SSO** lo que
`glpisaml` resolvía con su propio motor. Usar `_email_domain`/`_groups`/
claims mapeados como criterios (ver README). Exportar el XML de las reglas
nuevas como backup una vez armadas (botón nativo de export del engine).

## Paso 4 — Corte (ventana de mantenimiento)

1. **Backup de DB** antes de tocar nada (estándar, no específico de este
   plugin).
2. Desactivar `glpisaml` (desinstalar o al menos desactivarlo — no
   necesita estar desinstalado para que `sso` funcione, pero mantener dos
   plugins de SSO activos en simultáneo es confuso y hay que evitarlo en
   prod).
3. Activar el IdP en `sso` (`is_active = 1`).
4. **Forced SSO recomendado OFF** durante el corte: dejar que los usuarios
   elijan el botón, no auto-redirigir, hasta confirmar que el flujo
   funciona parejo para todos.
5. Anunciar la ventana al equipo con el plan de rollback (Paso 6) a mano.

## Paso 5 — Verificación post-corte

- [ ] Un puñado de usuarios reales (distintos perfiles/entidades) logean y
      caen en `user_adopted` (no `jit_created` — si aparece `jit_created`
      para un usuario que **debería** haber existido, el matching no está
      encontrando la cuenta: revisar `matching_field` vs. el formato real
      de `name`/email en `glpi_users`).
- [ ] Entidad/perfil/grupos post-login coinciden con lo que tenían antes
      (comparar contra el inventario del Paso 1).
- [ ] Logout cierra sesión en GLPI y en el IdP (Single Logout).
- [ ] `SELECT COUNT(*) FROM glpi_users WHERE authtype = 4` (EXTERNAL) crece
      de a uno por usuario que logueó — **no** hay picos de usuarios nuevos
      creados (`jit_created` en el log) si `jit_create` está OFF como
      corresponde a esta migración.

## Paso 6 — Plan de rollback

En cualquier momento, si algo no cierra:

1. **`?noSSO=1`** en la URL de login siempre disponible — un admin puede
   entrar por el form local (usuario DB local, o el mismo usuario si
   quedó con auth local además de EXTERNAL) sin depender del IdP.
2. Desactivar el IdP en `sso` (`is_active = 0`) — vuelve a mostrar sólo el
   form local para todos, sin desinstalar nada.
3. Si hace falta volver a `glpisaml` transitoriamente: no lo desinstalés
   en el Paso 4, sólo desactivalo — reactivar es inmediato. (Esto es sólo
   viable si `glpisaml` sigue siendo compatible con la versión de GLPI que
   esté corriendo en ese momento — si el rollback implica también volver
   de GLPI 11 a GLPI 10, es un rollback de infraestructura más amplio, no
   sólo de este plugin.)

## Paso 7 — Limpieza

Una vez confirmado estable (una semana de uso real sin incidentes es un
buen mínimo):

- [ ] Desinstalar `glpisaml` (libera sus tablas, cron, config).
- [ ] Activar Forced SSO si se decide simplificar el login a un solo botón.
- [ ] Revisar `Configuración > SSO > log_retention_days` acorde a la
      política de auditoría de prod (default 90 días).

# Instalación y configuración — SSO

## Instalación del plugin

1. Copiar `sso/` a `<GLPI>/plugins/sso/`.
2. **Configuración → Plugins → SSO → Instalar** (crea las 6 tablas +
   registra los crons) → **Activar**.
3. **Administración → Perfiles → [perfil] → SSO** → dar permiso
   (Super-Admin lo recibe automáticamente al instalar).
4. **Configuración → SSO** → configurar la **URL base pública** si difiere
   de la URL de GLPI (`$CFG_GLPI['url_base']`) — de ahí derivan las URLs de
   ACS/callback/metadata que hay que registrar en el IdP.

## Actualización sin pérdida de datos

Usar el runbook [UPGRADE.md](UPGRADE.md): backup validado → reemplazo del
artefacto completo → `php bin/console plugin:install --force sso` → activate →
validación y rollback. El install hook detecta una DB existente y ejecuta
migraciones aditivas/idempotentes; no recrea las tablas.

**No desinstalar para actualizar.** `plugin:uninstall sso` sí elimina las
tablas y reglas propias y se reserva exclusivamente para una desinstalación
intencional después de un backup.

Si venías de una versión previa, *Instalar* corre una migración
incremental (`Migration::addField`) que agrega columnas y tablas nuevas
sin borrar datos existentes.

> **Nota sobre el botón "+ Agregar" en Reglas de autorización SSO**: GLPI
> cachea el menú lateral en la sesión PHP del usuario. Si activaste el
> plugin o creaste la primera regla con una sesión ya abierta, **cerrá
> sesión y volvé a entrar** para que el botón aparezca — o entrá
> directamente a `plugins/sso/front/ruleauth.form.php`. No es un bug del
> plugin, es como GLPI maneja el menú en cualquier instancia de
> producción.

### Cron

Se registran automáticamente:

| Tarea | Frecuencia | Qué hace |
|---|---|---|
| `purgestate` | 15 min | Purga estado de flujo vencido (tokens, tickets, replay cache) |
| `purgelogs` | Diaria | Purga el registro de auditoría fuera de retención |
| `certwatch` | Diaria | Avisa sobre certificados SAML por vencer (<30 días) |

En producción conviene `CronTask::MODE_EXTERNAL` disparado por el cron del
sistema. En lab alcanza con el modo interno.

### Desinstalación

**Configuración → Plugins → SSO → Desinstalar** borra las 6 tablas, las
reglas de autorización (con sus criterios/acciones), el right de perfil, la
config global y desregistra los crons.

---

## Alta de un proveedor de identidad

**Configuración → SSO → + Agregar un proveedor de identidad.**

Campos comunes: nombre, activo, protocolo, ranking (orden en el login),
presentación (**Botón** o **Solo icono**), etiqueta e ícono. El modo botón
muestra el nombre elegido; el modo icono conserva ese nombre como texto
accesible y tooltip. El protocolo sólo se muestra en la configuración.

Aprovisionamiento (ver también el README):
- **Crear usuarios desconocidos (JIT)**: OFF por default. Actívalo sólo si
  querés que loguearse en el IdP cree la cuenta automáticamente.
- **Matchear usuarios existentes por**: email o login.
- **Perfil/entidad por defecto (JIT)**: nunca asignar un perfil con
  derechos de administración acá — usá las reglas de autorización para eso.
- **Dominios permitidos**: CSV; vacío = cualquier dominio.

---

## Provisioning SCIM 2.0

SCIM complementa JIT: el IdP puede crear, actualizar o desactivar cuentas y
sincronizar grupos sin esperar a que el usuario inicie sesión.

1. Guardá primero el IdP.
2. En su sección **Aprovisionamiento SCIM**, activá **Habilitar SCIM** y
   guardá.
3. Presioná **Generar token nuevo** y copiá el Bearer inmediatamente: se
   muestra una sola vez y GLPI conserva únicamente su SHA-256.
4. En el cliente de provisioning configurá:
   - Base URL: `https://tu-glpi/plugins/sso/front/scim.php/v2`
   - Authentication: Bearer token
   - User identifier: `externalId` estable; si no se envía, se usa
     `userName`.

Endpoints soportados:

| Recurso | Operaciones |
|---|---|
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | GET |
| `/Users` | GET/POST, filtro `userName eq "..."` o `externalId eq "..."` |
| `/Users/{id}` | GET/PUT/PATCH/DELETE |
| `/Groups` | GET/POST, filtro `displayName eq "..."` o `externalId eq "..."` |
| `/Groups/{id}` | GET/PUT/PATCH/DELETE, incluida membresía |

Mapeo SCIM → GLPI: `userName` → login, `name.familyName` → apellido,
`name.givenName` → nombre, primer `emails.value` → email dinámico, primer
`phoneNumbers.value` → teléfono y `active` → cuenta activa. El vínculo
persistente usa `(IdP, externalId)` y debe coincidir con el `sub` OIDC o
NameID SAML para que SCIM y SSO resuelvan al mismo usuario.

Seguridad y semántica:

- Un Bearer sólo accede a usuarios y grupos vinculados a su propio IdP.
- Rotar el token invalida inmediatamente el anterior; **Revocar token**
  corta SCIM sin desactivar el login SSO.
- `active=false` desactiva la cuenta y elimina best-effort sus sesiones PHP.
- DELETE de User hace soft-delete (`is_active=0`, `is_deleted=1`), nunca
  purge. DELETE de Group sólo elimina grupos creados por SCIM.
- Emails/membresías manuales (`is_dynamic=0`) no se quitan durante un
  replace SCIM.
- Fuera de alcance: `/Bulk`, `/Me`, ETags, ordenamiento y filtros complejos.

Keycloak no incluye un cliente SCIM nativo. Para validarlo se puede usar la
suite HTTP del proyecto; Entra Provisioning y Okta sí pueden apuntar directo
a la Base URL anterior.

---

## Guía: Keycloak (26+)

### SAML

1. **Clients → Create client**: Client type `SAML`, Client ID = la **URL de
   metadata del SP** que te muestra GLPI en el form del IdP (algo como
   `https://tu-glpi/plugins/sso/front/metadata.php?idp=N` — guardá el IdP
   una vez primero para tener el `N`, o usá cualquier string único y
   ajustalo después).
2. **Settings** del cliente:
   - Valid redirect URIs: `https://tu-glpi/plugins/sso/front/acs.php`
   - Name ID format: `email`
   - Force POST binding: ON
   - Sign assertions / Sign documents: ON (ambas — el plugin exige firma
     siempre)
   - Front channel logout: ON (para Single Logout)
   - Logout Service Redirect Binding URL:
     `https://tu-glpi/plugins/sso/front/sls.php`
3. **Realm settings → Keys**: copiá el certificado de firma RS256
   (`Certificate` del key con `use: SIG`).
4. En GLPI, alta del IdP con protocolo SAML: pegá el **XML de metadata del
   realm** (`https://tu-keycloak/realms/TU-REALM/protocol/saml/descriptor`)
   en "Importar metadata del IdP" — autocompleta entity ID, SSO URL, SLO
   URL y certificado. Revisá que el certificado haya quedado bien pegado.

### OIDC

1. **Clients → Create client**: Client type `OpenID Connect`.
2. **Capability config**: Client authentication ON (confidential),
   Standard flow ON, Direct access grants OFF.
3. **Settings**:
   - Valid redirect URIs: `https://tu-glpi/plugins/sso/front/callback.php`
   - Valid post logout redirect URIs: `https://tu-glpi/*`
4. **Credentials** → copiá el **Client secret**.
5. En GLPI: Issuer URL = `https://tu-keycloak/realms/TU-REALM`, Client ID y
   Client secret del paso anterior. El discovery resuelve el resto solo.

**Grupos como claim**: agregá un *Protocol Mapper* de tipo "Group
Membership" al cliente (nombre del claim: `groups`, full path OFF si
preferís nombres simples) para que el claim `groups` llegue con los grupos
del usuario — es lo que lee el criterio "Grupos" del motor de reglas
(configurable por IdP, campo "Claim/atributo de grupos").

---

## Guía: Microsoft Entra ID

### OIDC (recomendado sobre SAML para Entra)

1. **App registrations → New registration**.
   - Redirect URI (Web): `https://tu-glpi/plugins/sso/front/callback.php`
2. **Authentication**: agregá también, si vas a usar logout,
   `https://tu-glpi/*` como *Front-channel logout URL* no aplica igual que
   en Keycloak — Entra usa el flujo estándar `end_session_endpoint`, que el
   plugin ya maneja vía discovery.
3. **Certificates & secrets → New client secret** — copiá el **value** (no
   el secret ID).
4. **API permissions**: `openid`, `profile`, `email` (delegados, suelen
   venir por default).
5. En GLPI: Issuer URL = `https://login.microsoftonline.com/<tenant-id>/v2.0`,
   Client ID = Application (client) ID, Client secret del paso 3.

> **Gotcha de grupos en Entra**: por default el claim `groups` trae
> **GUIDs**, no nombres. Dos opciones: (a) matchear las reglas de
> autorización por GUID en vez de nombre, o (b) en **Token configuration**
> del app registration, agregar el claim opcional `groups` con formato
> "sAMAccountName" o "NetBIOS domain\sAMAccountName" para que lleguen
> nombres legibles (requiere que el tenant tenga esos atributos
> sincronizados). Si el usuario pertenece a muchos grupos (>200 por
> default), Entra emite un `_claim_names`/overage indicator en vez del
> listado — para ese caso hay que consultar Microsoft Graph aparte, fuera
> de alcance de este plugin (usar dominio de email o un claim de rol de
> aplicación en su lugar).

### SAML

Análogo a Keycloak: **Enterprise applications → New application → Create
your own application → SAML**. Entity ID / Reply URL = la URL de metadata
del SP / `acs.php` de GLPI. Entra permite subir el XML de metadata del SP
directamente (Basic SAML Configuration → Upload metadata file) en vez de
tipear cada campo.

---

## Guía: Google Workspace (OIDC)

1. **Google Cloud Console → APIs & Services → Credentials → Create
   credentials → OAuth client ID** (tipo *Web application*).
2. Authorized redirect URIs: `https://tu-glpi/plugins/sso/front/callback.php`.
3. En GLPI: Issuer URL = `https://accounts.google.com`, Client ID y Client
   secret de la consola.
4. Google no expone grupos por el claim `groups` estándar — si necesitás
   reglas por grupo de Workspace, hace falta Directory API aparte (no
   soportado en v1; usar dominio de email como criterio, que sí viene en
   `email`/`hd`).

---

## Troubleshooting

- **`redirect_uri_mismatch` / `invalid_redirect_uri`**: la URL base
  configurada en **Configuración → SSO** (o `$CFG_GLPI['url_base']` si la
  dejaste vacía) no coincide exactamente (protocolo, host, puerto, sin
  barra final) con lo registrado en el IdP.
- **Login rechazado sin mensaje claro**: mirá **Configuración → SSO →
  Registro** — cada rechazo queda logueado con el motivo (regla que negó,
  dominio no permitido, email no verificado, firma inválida, etc.). Nunca
  se muestra el detalle técnico en el navegador a propósito.
- **El botón del IdP no aparece en el login**: el IdP tiene que estar
  **activo**. Revisá también que no esté oculto por Forced SSO (que
  auto-redirige) — en ese caso seguís viendo el botón igual como fallback.
- **Certificado SAML rechazado como inválido**: confirmá que el campo
  quedó con el PEM completo (o el plugin lo puede tomar "pelado", sin
  `BEGIN/END CERTIFICATE` — se normaliza solo para el chequeo de
  vencimiento, pero para la *validación de firma* SAML sí importa el
  formato exacto que usa `onelogin/php-saml`; preferí siempre pegar el PEM
  completo con headers).

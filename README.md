# SSO — plugin de autenticación para GLPI 11

Service Provider / Relying Party completo dentro de GLPI: login contra
proveedores de identidad externos vía **SAML 2.0** y **OpenID Connect**,
multi-IdP, aprovisionamiento JIT/SCIM, autorización por el **motor de reglas
nativo de GLPI** (el mismo que usan las reglas LDAP — Administración >
Reglas), y **Single Logout**.

Compatible únicamente con **GLPI 11.x** (PHP 8.2+, MariaDB).

---

## Qué hace

El usuario clickea "Iniciar sesión con `<IdP>`" (o es redirigido
automáticamente con Forced SSO), se autentica en Keycloak / Entra ID /
Google / Okta / cualquier IdP SAML u OIDC, y vuelve a GLPI con sesión
iniciada, usuario aprovisionado/actualizado, y entidad/perfil/grupos
asignados por reglas.

**No es un IdP** — sólo actúa como SP (SAML) / RP (OIDC), no emite tokens.
**No reemplaza LDAP/CAS** — GLPI core ya los trae (Setup > Authentication);
el gap real del core es exactamente SAML + OIDC.

### Multi-IdP

Cada proveedor configurado (`Idp`) tiene su propio protocolo, botón en el
login, y opciones de aprovisionamiento/matching. El form ramifica por
protocolo (SAML/OIDC) con toggle JS. Import de metadata asistido: pegás la
URL o el XML del IdP y autocompleta entity ID / endpoints / certificados
(SAML), o usás discovery automático desde la Issuer URL (OIDC).

Cada proveedor puede mostrarse en el login como botón descriptivo o como
icono compacto. La configuración incluye vista previa, presets de marca y
etiquetas accesibles para que el modo icono no dependa de adivinar la imagen.

### Login SAML

SP-initiated únicamente (IdP-initiated está bloqueado por diseño — es un
vector de CSRF de login). Firma requerida siempre, `InResponseTo` validado
contra el estado del login, cache anti-replay por assertion ID.

### Login OIDC

Authorization Code + PKCE (S256) siempre, nunca implicit. ID token validado
completo: whitelist de algoritmos (RS256/ES256, jamás `none`), firma contra
JWKS con refresh automático ante rotación de claves, issuer y audience
exactos, nonce, clock skew ±90s.

### Aprovisionamiento

- **Matching**: usuarios existentes se vinculan por email o login en el
  primer login (adopción — pasan a `authtype = EXTERNAL`).
- **JIT (Just-In-Time)**: crear usuarios nuevos automáticamente es
  **configurable por IdP y está OFF por default** — autenticarse en el IdP
  no crea una cuenta en GLPI salvo que se habilite a propósito.
- **Identidad estable**: el vínculo `(IdP, subject)` sobrevive cambios de
  email en el IdP (usa el `sub` OIDC / `NameID` SAML, no el email, como
  clave persistente después de la primera vinculación).
- **SCIM 2.0**: lifecycle push de Users y Groups con Bearer independiente
  por IdP. Permite crear/actualizar/desactivar usuarios y sincronizar grupos
  sin esperar al próximo login. Los tokens se guardan sólo como SHA-256.

### Provisioning SCIM 2.0

Endpoint: `https://tu-glpi/plugins/sso/front/scim.php/v2`. Implementa
discovery, `Users`, `Groups`, filtro `eq`, paginación básica, PUT/PATCH y
DELETE. Cada Bearer sólo puede ver y modificar recursos vinculados a su IdP;
los grupos creados por SCIM quedan marcados como administrados por ese IdP.

`active=false` desactiva la cuenta e invalida best-effort sus sesiones PHP.
DELETE de User es siempre **soft-delete**; nunca purga el usuario ni rompe
referencias de tickets/activos. Las asignaciones manuales de emails,
perfiles y grupos no son eliminadas por una sincronización SCIM.

### Autorización — motor de reglas nativo

Nada de un editor propio: las reglas viven en **Administración > Reglas >
Reglas de autorización SSO**, con la UI estándar completa de GLPI
(criterios múltiples AND/OR, N acciones por regla, ranking, test/preview,
export/import XML).

Criterios disponibles: IdP, protocolo, login, email, **dominio del email**,
**grupos** (multivaluado, leído del claim/atributo que configures por IdP),
nombre/apellido, y **cualquier claim mapeado** en un IdP se expone
automáticamente como criterio (`Claim: <nombre>`).

Acciones: asignar entidad (+recursivo), asignar perfil (acumulable entre
reglas, igual que las reglas LDAP), agregar a grupo, activo/inactivo,
entidad/perfil por defecto, timezone, idioma, **denegar login**.

Ejemplo típico:

> *email termina con* `@acme.com` → perfil **Self-Service**, entidad
> **ACME**

Las asignaciones son **dinámicas** (mismo mecanismo que LDAP): si en un
login posterior la regla ya no matchea, el perfil/grupo que había dado se
retira solo — sin tocar lo que un admin asignó a mano.

### Forced SSO / HRD / bypass de emergencia

- **Forced SSO**: auto-redirect del login al IdP configurado como default.
- **HRD** (Home Realm Discovery): con varios IdPs, el usuario ingresa su
  email y el JS resuelve el IdP correcto por dominio — sin que el email
  viaje en ninguna URL.
- **Bypass `?noSSO=1`**: siempre disponible, incluso con Forced SSO activo.
  El plugin nunca desactiva el formulario de login local — sólo lo esconde.

### Single Logout

Al cerrar sesión en GLPI, se cierra también la sesión del IdP:
`end_session_endpoint` + `id_token_hint` (OIDC), `LogoutRequest` SAML
firmado (SP-initiated). También atiende `LogoutRequest` **IdP-initiated**
(si el usuario cierra sesión desde otra app federada al mismo IdP, GLPI se
entera y mata su sesión). Configurable (`idp_logout`, default ON).

### Auditoría

Cada evento de auth (login ok/denegado, JIT, adopción, regla matcheada,
logout, error de validación) queda en **Configuración > SSO > Registro**,
con retención configurable y purga automática por cron. Nunca guarda
tokens ni assertions completas, ni siquiera en modo debug.

### Vigilancia de certificados

Cron diario que avisa (log + banner en el form del IdP) cuando un
certificado SAML (IdP o SP) vence en menos de 30 días.

---

## Arquitectura (resumen)

```
sso/
├── src/            GlpiPlugin\Sso\* — Idp, SamlClient, OidcClient,
│                   LoginPipeline, RuleAuth(Collection), UserLink,
│                   RequestState, Config, Log, CertWatch, ScimServer, ...
├── front/          login/acs/callback/finish/metadata/sls/logout/scim.php
│                   (públicos) + idp/config/log/ruleauth (autenticados)
├── vendor/         onelogin/php-saml, xmlseclibs, firebase/php-jwt
│                   (vendoreados, sin composer — autoloader propio)
├── sql/            install.sql
└── locales/        es_AR / es_ES / es_MX
```

El estado de flujo (state OIDC, AuthnRequest SAML, tickets de finalización,
cache anti-replay) vive **en DB con TTL corto**, nunca en la sesión PHP —
el POST del ACS SAML es cross-site y `SameSite` no deja viajar la cookie de
sesión en ese request.

---

## Instalación

Ver [INSTALL.md](INSTALL.md) — instalación, guía de configuración por IdP
(Keycloak, Entra ID, Google) y troubleshooting.

Para pasar de una versión a otra sin perder DB/configuración, seguir
[UPGRADE.md](UPGRADE.md). La actualización usa `plugin:install --force`; nunca
se debe desinstalar el plugin como paso de upgrade.

## Migrando desde `glpisaml`

Ver [MIGRATION.md](MIGRATION.md) — runbook completo con plan de
coexistencia y rollback.

---

## Licencia

GPLv3. Ver encabezado en `setup.php`.

## Autor

Jonatan Riccillo

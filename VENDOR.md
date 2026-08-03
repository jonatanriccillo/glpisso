# Vendor — dependencias PHP vendoreadas

Sin composer en runtime: las libs viven en `vendor/` con un autoloader
mínimo propio (`vendor/autoload.php`) y se actualizan A MANO copiando el
árbol `src/` del release upstream. Este manifiesto fija versión, licencia
y checksum agregado de cada una; `tools/verify_vendor.sh` lo verifica (lo
corre también el CI).

| Librería | Versión | Licencia | Upstream |
|---|---|---|---|
| `onelogin/php-saml` | 4.3.2 | MIT | https://github.com/SAML-Toolkits/php-saml |
| `robrichards/xmlseclibs` | 3.1.5 | BSD-3-Clause | https://github.com/robrichards/xmlseclibs |
| `firebase/php-jwt` | 6.11.1 | BSD-3-Clause | https://github.com/firebase/php-jwt |

## Checksums

SHA-256 agregado por librería: `find <dir> -type f | LC_ALL=C sort |
xargs sha256sum | sed 's/ \*/  /' | sha256sum` (orden estable, cubre
contenido y nombres; el `sed` normaliza el marcador binario `*` que emite
el sha256sum de Windows para que el valor sea idéntico en Linux/Windows).

```
onelogin/php-saml       99ca8b319f7ce5b4d9ee8ee0e26105a4a51cbec26584c80fc525ec5f7e41ee29  (26 archivos)
robrichards/xmlseclibs  e3e7d6d7f73dd9b1fe175b0e635499a1255f015b0a26ea1d85b21e238b028197  (5 archivos)
firebase/php-jwt        bb7cff7a3f73bfa90e8731a1f0d551d60b9d10917cf9c4704097911a7df5691e  (9 archivos)
autoload.php            95f8ff36ffd9eb8088090d4c450d2a7ba711708403d385bb7a9759a4522f4e38
```

## Cómo actualizar una lib

1. Bajar el release upstream, verificar su tag/checksum publicado.
2. Reemplazar el subárbol en `vendor/<vendor>/<lib>/` completo (no merge).
3. Recalcular los checksums de arriba y actualizar la tabla + versión.
4. Correr `sh tools/verify_vendor.sh` y `php tests/php/run.php`.
5. Anotar el cambio en `CHANGELOG.md` (las CVEs de estas libs son CVEs
   nuestras: revisar advisories upstream en cada release propio).

#!/bin/sh
# Empaqueta el plugin para distribución: sso-<version>.tar.gz + .sha256.
# Excluye tests, herramientas de desarrollo, docs internas y basura.
# Uso: sh tools/package.sh [directorio_salida]   (default: dist/)
set -e
cd "$(dirname "$0")/.."

VERSION=$(sed -n "s/^define('PLUGIN_SSO_VERSION', '\(.*\)');$/\1/p" setup.php)
[ -n "$VERSION" ] || { echo "No pude leer PLUGIN_SSO_VERSION de setup.php"; exit 1; }

OUT="${1:-dist}"
mkdir -p "$OUT"
PKG="$OUT/sso-$VERSION.tar.gz"

# Verificaciones previas: vendor íntegro y tests puros en verde.
sh tools/verify_vendor.sh
php tests/php/run.php > /dev/null || { echo "Tests puros en rojo: no se empaqueta"; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/sso"

tar -cf - \
    --exclude='./.git' \
    --exclude='./.gitignore' \
    --exclude='./.github' \
    --exclude='./.codebase-memory' \
    --exclude='./dist' \
    --exclude='./tests' \
    --exclude='./tools' \
    --exclude='./BLUEPRINT.md' \
    --exclude='./PLAN.md' \
    --exclude='./*.tar.gz' \
    . | tar -xf - -C "$STAGE/sso"

tar -czf "$PKG" -C "$STAGE" sso
( cd "$OUT" && sha256sum "$(basename "$PKG")" > "$(basename "$PKG").sha256" )

echo "Paquete: $PKG"
cat "$PKG.sha256"

#!/bin/sh
# Verifica que vendor/ coincida byte a byte con el manifiesto VENDOR.md.
# Uso: sh tools/verify_vendor.sh   (exit 0 = íntegro)
set -e
cd "$(dirname "$0")/.."

fail=0
check() {
    dir="$1"; expected="$2"
    # sed: el sha256sum de Windows marca binario con "hash *path"; se
    # normaliza al formato Linux "hash  path" para que el agregado coincida.
    actual=$(find "vendor/$dir" -type f | LC_ALL=C sort | xargs sha256sum | sed 's/ \*/  /' | sha256sum | cut -d' ' -f1)
    if [ "$actual" = "$expected" ]; then
        echo "OK   vendor/$dir"
    else
        echo "FAIL vendor/$dir: sha256 $actual != $expected (¿modificado a mano?)"
        fail=1
    fi
}

check onelogin/php-saml       99ca8b319f7ce5b4d9ee8ee0e26105a4a51cbec26584c80fc525ec5f7e41ee29
check robrichards/xmlseclibs  e3e7d6d7f73dd9b1fe175b0e635499a1255f015b0a26ea1d85b21e238b028197
check firebase/php-jwt        bb7cff7a3f73bfa90e8731a1f0d551d60b9d10917cf9c4704097911a7df5691e

autoload=$(sha256sum vendor/autoload.php | cut -d' ' -f1)
if [ "$autoload" = "95f8ff36ffd9eb8088090d4c450d2a7ba711708403d385bb7a9759a4522f4e38" ]; then
    echo "OK   vendor/autoload.php"
else
    echo "FAIL vendor/autoload.php: sha256 $autoload"
    fail=1
fi

exit $fail

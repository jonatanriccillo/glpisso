#!/bin/sh
# Ciclo de vida del plugin sso en una instancia GLPI 11.0.8 DESCARTABLE:
# install 0.2.13 → upgrade 0.3.0-rc1 → --force idempotente → uninstall → install limpia.
set -e

APP=sso-qa-app; DB=sso-qa-db; NET=sso-qa-net
CONSOLE="docker exec -u www-data -w /var/www/glpi $APP php bin/console"
SQL() { docker exec $DB mariadb -uglpi -pglpi glpi -N -e "$1" 2>/dev/null; }

cleanup() { docker rm -f $APP $DB >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "== levantando instancia descartable =="
docker network create $NET >/dev/null
docker run -d --name $DB --network $NET -e MARIADB_ROOT_PASSWORD=qa \
  -e MARIADB_DATABASE=glpi -e MARIADB_USER=glpi -e MARIADB_PASSWORD=glpi mariadb:10.11 >/dev/null
docker run -d --name $APP --network $NET -e GLPI_DB_HOST=$DB -e GLPI_DB_PORT=3306 -e GLPI_INSTALL_MODE=DOCKER -e GLPI_DB_NAME=glpi \
  -e GLPI_DB_USER=glpi -e GLPI_DB_PASSWORD=glpi glpi/glpi:11.0.8 >/dev/null

echo "esperando auto-install de GLPI (hasta 300s)..."
for i in $(seq 1 60); do
  sleep 5
  if $CONSOLE database:update --no-interaction >/tmp/qa_dbu.log 2>&1; then READY=1; break; fi
done
[ "${READY:-0}" = "1" ] || { echo "FAIL: GLPI no quedo listo"; tail -5 /tmp/qa_dbu.log; exit 1; }
echo "GLPI listo tras ~$((i*5))s"

echo "== 1. install 0.2.13 =="
tar -xzf /tmp/sso-0213.tar.gz -C /tmp
docker cp /tmp/sso $APP:/var/www/glpi/plugins/sso
docker exec -u root $APP chown -R www-data:www-data /var/www/glpi/plugins/sso
$CONSOLE plugin:install sso
$CONSOLE plugin:activate sso
echo "tablas: $(SQL "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='glpi' AND table_name LIKE 'glpi\_plugin\_sso\_%'") (espero 6)"
echo "version DB: $(SQL "SELECT version FROM glpi_plugins WHERE directory='sso'") (espero 0.2.13)"
echo "crons: $(SQL "SELECT COUNT(*) FROM glpi_crontasks WHERE itemtype LIKE '%Sso%'")"

echo "== 2. upgrade a 0.3.0-rc1 =="
docker exec -u root $APP rm -rf /var/www/glpi/plugins/sso
docker cp /tmp/sso_up/sso $APP:/var/www/glpi/plugins/sso
docker exec -u root $APP chown -R www-data:www-data /var/www/glpi/plugins/sso
$CONSOLE plugin:install --force sso <<A
Yes
A
$CONSOLE plugin:activate sso
echo "version DB: $(SQL "SELECT version FROM glpi_plugins WHERE directory='sso'") state: $(SQL "SELECT state FROM glpi_plugins WHERE directory='sso'") (espero 0.3.0-rc1 / 1)"
echo "tablas: $(SQL "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='glpi' AND table_name LIKE 'glpi\_plugin\_sso\_%'") (espero 6)"

echo "== 3. --force de nuevo (idempotencia, los datos sobreviven) =="
SQL "INSERT INTO glpi_plugin_sso_idps (name, protocol, is_active) VALUES ('canario', 'oidc', 0)"
$CONSOLE plugin:install --force sso <<A
Yes
A
$CONSOLE plugin:activate sso
echo "canario sobrevive: $(SQL "SELECT COUNT(*) FROM glpi_plugin_sso_idps WHERE name='canario'") (espero 1)"

echo "== 4. uninstall sin residuos =="
$CONSOLE plugin:deactivate sso
$CONSOLE plugin:uninstall sso <<A
Yes
A
echo "tablas restantes: $(SQL "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='glpi' AND table_name LIKE 'glpi\_plugin\_sso\_%'") (espero 0)"
echo "crons restantes: $(SQL "SELECT COUNT(*) FROM glpi_crontasks WHERE itemtype LIKE '%Sso%'") (espero 0)"
echo "profilerights restantes: $(SQL "SELECT COUNT(*) FROM glpi_profilerights WHERE name LIKE 'plugin_sso%'") (espero 0)"
echo "configs restantes: $(SQL "SELECT COUNT(*) FROM glpi_configs WHERE context='plugin:sso'") (espero 0)"

echo "== 5. install limpia 0.3.0-rc1 =="
$CONSOLE plugin:install sso
$CONSOLE plugin:activate sso
echo "version DB: $(SQL "SELECT version FROM glpi_plugins WHERE directory='sso'") state: $(SQL "SELECT state FROM glpi_plugins WHERE directory='sso'")"
echo "tablas: $(SQL "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='glpi' AND table_name LIKE 'glpi\_plugin\_sso\_%'") (espero 6)"

echo "== LISTO: destruyendo instancia descartable =="

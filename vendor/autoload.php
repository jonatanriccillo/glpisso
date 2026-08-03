<?php
/**
 * Autoloader mínimo para las libs vendoreadas (sin composer):
 *  - onelogin/php-saml 4.3.2  → OneLogin\Saml2\
 *  - robrichards/xmlseclibs 3.1.5 → RobRichards\XMLSecLibs\
 *  - firebase/php-jwt 6.11.1  → Firebase\JWT\
 */

spl_autoload_register(function (string $class): void {
    $prefixes = [
        'OneLogin\\Saml2\\'         => __DIR__ . '/onelogin/php-saml/src/Saml2/',
        'RobRichards\\XMLSecLibs\\' => __DIR__ . '/robrichards/xmlseclibs/src/',
        'Firebase\\JWT\\'           => __DIR__ . '/firebase/php-jwt/src/',
    ];
    foreach ($prefixes as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});

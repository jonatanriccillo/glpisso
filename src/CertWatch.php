<?php

namespace GlpiPlugin\Sso;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Vigilancia de certificados X.509 (BLUEPRINT §2 "Vigilancia de
 * certificados"): un cert IdP/SP vencido en silencio es el clásico
 * "el SSO murió un lunes". Cron `certwatch` corre esto diario.
 */
class CertWatch
{
    public const WARN_DAYS = 30;

    /**
     * @return array<int, array{idps_id:int, name:string, field:string, label:string, days_left:int, expires_at:string}>
     *         certificados que vencen en <= WARN_DAYS (o ya vencidos, días negativos)
     */
    public static function check(): array
    {
        $warnings = [];
        foreach (Idp::getActive() as $row) {
            if ($row['protocol'] !== Idp::PROTO_SAML) {
                continue; // OIDC no maneja certs propios (rotación vía JWKS)
            }
            $idp = new Idp();
            if (!$idp->getFromDB((int) $row['id'])) {
                continue;
            }
            foreach ([
                'idp_x509cert' => __('IdP certificate', 'sso'),
                'sp_x509cert'  => __('SP certificate', 'sso'),
            ] as $field => $label) {
                $pem = trim((string) $idp->fields[$field]);
                if ($pem === '') {
                    continue;
                }
                $days_left = self::daysUntilExpiration($pem);
                if ($days_left !== null && $days_left <= self::WARN_DAYS) {
                    $warnings[] = [
                        'idps_id'    => (int) $idp->getID(),
                        'name'       => (string) $idp->fields['name'],
                        'field'      => $field,
                        'label'      => $label,
                        'days_left'  => $days_left,
                        'expires_at' => self::expirationDate($pem) ?? '',
                    ];
                }
            }
        }
        return $warnings;
    }

    /** Corre el chequeo y deja un log por certificado en alerta. */
    public static function checkAndLog(): int
    {
        $warnings = self::check();
        foreach ($warnings as $w) {
            $expired = $w['days_left'] < 0;
            Log::record(
                'cert_expiring',
                $expired ? Log::LEVEL_ERROR : Log::LEVEL_WARNING,
                sprintf(
                    $expired
                        ? __('%1$s (%2$s) expired %3$d days ago', 'sso')
                        : __('%1$s (%2$s) expires in %3$d days', 'sso'),
                    $w['label'],
                    $w['name'],
                    abs($w['days_left'])
                ),
                ['idps_id' => $w['idps_id']]
            );
        }
        return count($warnings);
    }

    /** null si el PEM no parsea. */
    public static function daysUntilExpiration(string $pem): ?int
    {
        $normalized = self::normalizePem($pem);
        $parsed = @openssl_x509_parse($normalized);
        if ($parsed === false || !isset($parsed['validTo_time_t'])) {
            return null;
        }
        return (int) floor(((int) $parsed['validTo_time_t'] - time()) / DAY_TIMESTAMP);
    }

    public static function expirationDate(string $pem): ?string
    {
        $normalized = self::normalizePem($pem);
        $parsed = @openssl_x509_parse($normalized);
        if ($parsed === false || !isset($parsed['validTo_time_t'])) {
            return null;
        }
        return date('Y-m-d', (int) $parsed['validTo_time_t']);
    }

    /** IdPs suelen pegar el cert "pelado" (sin BEGIN/END) — se lo agregamos si falta. */
    private static function normalizePem(string $pem): string
    {
        $pem = trim($pem);
        if (str_contains($pem, '-----BEGIN')) {
            return $pem;
        }
        $pem = preg_replace('/\s+/', '', $pem) ?? $pem;
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($pem, 64, "\n") . "-----END CERTIFICATE-----\n";
    }
}

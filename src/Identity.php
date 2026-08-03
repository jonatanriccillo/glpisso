<?php

namespace GlpiPlugin\Sso;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * Identidad normalizada resultante de una autenticación (SAML u OIDC).
 * Es lo único que consume LoginPipeline: los clientes de protocolo la
 * producen y acá muere toda diferencia entre familias.
 */
class Identity
{
    /**
     * @param string     $subject        NameID (SAML) o `sub` (OIDC) — identidad estable
     * @param array      $claims         claim/atributo => string|string[] (aplanado)
     * @param string     $email          email resuelto ('' si no vino)
     * @param bool|null  $email_verified null = el protocolo no lo informa (SAML)
     */
    public function __construct(
        public readonly string $subject,
        public readonly array $claims = [],
        public readonly string $email = '',
        public readonly ?bool $email_verified = null,
    ) {
    }

    /** Primer valor escalar de un claim (o '' si no está). */
    public function claim(string $key): string
    {
        $value = $this->claims[$key] ?? '';
        if (is_array($value)) {
            $value = $value[0] ?? '';
        }
        return trim((string) $value);
    }

    /** Todos los valores de un claim como lista (para multivaluados: grupos). */
    public function claimList(string $key): array
    {
        $value = $this->claims[$key] ?? [];
        if (!is_array($value)) {
            $value = $value === '' ? [] : [$value];
        }
        return array_values(array_filter(array_map('strval', $value), fn($v) => $v !== ''));
    }

    /** Dominio del email en minúsculas ('' si no hay email). */
    public function emailDomain(): string
    {
        $at = strrpos($this->email, '@');
        return $at === false ? '' : strtolower(substr($this->email, $at + 1));
    }

    /** Serialización para el ticket one-shot (RequestState). */
    public function toArray(): array
    {
        return [
            'subject'        => $this->subject,
            'claims'         => $this->claims,
            'email'          => $this->email,
            'email_verified' => $this->email_verified,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['subject'] ?? ''),
            is_array($data['claims'] ?? null) ? $data['claims'] : [],
            (string) ($data['email'] ?? ''),
            isset($data['email_verified']) ? (bool) $data['email_verified'] : null,
        );
    }
}

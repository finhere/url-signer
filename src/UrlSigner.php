<?php

declare(strict_types=1);

namespace UrlSigner;

/**
 * Stateless signed URLs using HMAC-SHA256 with an expiry claim.
 */
final class UrlSigner
{
    private string $secret;

    public function __construct(string $secret)
    {
        if (strlen($secret) < 16) {
            throw new \InvalidArgumentException('signing secret too short');
        }
        $this->secret = $secret;
    }

    /**
     * Return $base with a canonical, signed query string appended.
     */
    public function sign(string $base, array $params = [], int $ttl = 600): string
    {
        $params['exp'] = time() + max(1, $ttl);
        $canonical = $this->canonical($params);
        $sig = hash_hmac('sha256', $canonical, $this->secret);
        return $base . '?' . $canonical . '&sig=' . $sig;
    }

    /**
     * Verify a full request URI (or any "...?a=b&sig=..." string).
     */
    public function verify(string $uri): bool
    {
        $qs = (string) parse_url($uri, PHP_URL_QUERY);
        if ($qs === '') {
            return false;
        }
        parse_str($qs, $params);
        $sig = (string) ($params['sig'] ?? '');
        unset($params['sig']);
        if ($sig === '' || !isset($params['exp'])) {
            return false;
        }
        if ((int) $params['exp'] < time()) {
            return false;
        }
        $expected = hash_hmac('sha256', $this->canonical($params), $this->secret);
        return hash_equals($expected, $sig);
    }

    /**
     * Verify against several accepted secrets (for key rotation).
     */
    public function verifyWithKeys(string $uri, array $secrets): bool
    {
        foreach ($secrets as $s) {
            if ((new self($s))->verify($uri)) {
                return true;
            }
        }
        return false;
    }

    private function canonical(array $params): string
    {
        ksort($params);
        $parts = [];
        foreach ($params as $k => $v) {
            $parts[] = rawurlencode((string) $k) . '=' . rawurlencode((string) $v);
        }
        return implode('&', $parts);
    }
}

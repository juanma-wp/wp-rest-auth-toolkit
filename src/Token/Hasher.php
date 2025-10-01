<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Token;

/**
 * Token Hasher
 *
 * Provides secure HMAC-based hashing for tokens before database storage.
 * Tokens should always be hashed before storage to prevent token theft
 * in case of database compromise.
 *
 * @package WPRestAuth\AuthToolkit\Token
 */
class Hasher
{
    private string $secret;
    private string $algorithm;

    /**
     * @param string $secret Secret key for HMAC hashing
     * @param string $algorithm Hash algorithm (default: sha256)
     */
    public function __construct(string $secret, string $algorithm = 'sha256')
    {
        if (empty($secret)) {
            throw new \InvalidArgumentException('Hash secret cannot be empty');
        }

        if (!in_array($algorithm, hash_algos(), true)) {
            throw new \InvalidArgumentException("Unsupported hash algorithm: {$algorithm}");
        }

        $this->secret = $secret;
        $this->algorithm = $algorithm;
    }

    /**
     * Hash a token using HMAC
     *
     * @param string $token Token to hash
     * @return string Hashed token (hexadecimal)
     */
    public function hash(string $token): string
    {
        return hash_hmac($this->algorithm, $token, $this->secret);
    }

    /**
     * Verify a token against its hash (timing-safe comparison)
     *
     * @param string $token Plain token
     * @param string $hash Stored hash
     * @return bool True if token matches hash
     */
    public function verify(string $token, string $hash): bool
    {
        $computed_hash = $this->hash($token);
        return hash_equals($hash, $computed_hash);
    }

    /**
     * Static helper for quick hashing
     *
     * @param string $token Token to hash
     * @param string $secret Secret key
     * @param string $algorithm Hash algorithm
     * @return string Hashed token
     */
    public static function make(string $token, string $secret, string $algorithm = 'sha256'): string
    {
        $hasher = new self($secret, $algorithm);
        return $hasher->hash($token);
    }
}

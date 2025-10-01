<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Token;

/**
 * Cryptographically Secure Token Generator
 *
 * Generates random tokens for refresh tokens, authorization codes,
 * and other security-sensitive operations.
 *
 * @package WPRestAuth\AuthToolkit\Token
 */
class Generator
{
    /**
     * Generate a secure random token
     *
     * @param int $length Token length in characters (must be even)
     * @return string Hexadecimal token string
     * @throws \InvalidArgumentException If length is invalid
     */
    public static function generate(int $length = 64): string
    {
        if ($length <= 0 || $length % 2 !== 0) {
            throw new \InvalidArgumentException('Token length must be a positive even number');
        }

        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }

        // Fallback for environments without random_bytes
        // This should rarely be needed on PHP 7.4+
        return self::fallbackGenerate($length);
    }

    /**
     * Fallback token generation using WordPress function
     *
     * @param int $length Token length
     * @return string Generated token
     */
    private static function fallbackGenerate(int $length): string
    {
        // Try WordPress password generator if available
        if (function_exists('wp_generate_password')) {
            return wp_generate_password($length, false);
        }

        // Last resort: use openssl
        if (function_exists('openssl_random_pseudo_bytes')) {
            return bin2hex(openssl_random_pseudo_bytes($length / 2));
        }

        throw new \RuntimeException('No secure random number generator available');
    }

    /**
     * Generate authorization code (shorter token)
     *
     * @return string 32-character authorization code
     */
    public static function authorizationCode(): string
    {
        return self::generate(32);
    }

    /**
     * Generate access token
     *
     * @return string 48-character access token
     */
    public static function accessToken(): string
    {
        return self::generate(48);
    }

    /**
     * Generate refresh token (longer for enhanced security)
     *
     * @return string 64-character refresh token
     */
    public static function refreshToken(): string
    {
        return self::generate(64);
    }

    /**
     * Generate PKCE code verifier (RFC 7636)
     *
     * @return string 43-128 character code verifier
     */
    public static function pkceVerifier(): string
    {
        // Generate 32 random bytes = 43 base64url chars (minimum length)
        $bytes = random_bytes(32);
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

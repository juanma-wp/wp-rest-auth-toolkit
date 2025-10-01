<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\OAuth2;

use WPRestAuth\AuthToolkit\JWT\Base64Url;

/**
 * PKCE (Proof Key for Code Exchange) Handler
 *
 * Implements RFC 7636 - PKCE for OAuth 2.0 Public Clients.
 * Provides protection against authorization code interception attacks
 * for public clients (mobile apps, SPAs) that cannot securely store secrets.
 *
 * @package WPRestAuth\AuthToolkit\OAuth2
 */
class Pkce
{
    /**
     * Supported code challenge methods
     */
    private const SUPPORTED_METHODS = ['S256', 'plain'];

    /**
     * Code verifier length constraints (RFC 7636)
     */
    private const MIN_VERIFIER_LENGTH = 43;
    private const MAX_VERIFIER_LENGTH = 128;

    /**
     * Generate a PKCE code verifier
     *
     * Creates a cryptographically random string of 43-128 characters
     * from the character set [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
     *
     * @param int $length Verifier length (default: 43, minimum)
     * @return string Code verifier
     * @throws \InvalidArgumentException If length is invalid
     */
    public static function generateVerifier(int $length = 43): string
    {
        if ($length < self::MIN_VERIFIER_LENGTH || $length > self::MAX_VERIFIER_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Code verifier length must be between %d and %d characters',
                    self::MIN_VERIFIER_LENGTH,
                    self::MAX_VERIFIER_LENGTH
                )
            );
        }

        // Generate random bytes and encode as base64url
        $bytes = random_bytes((int) ceil($length * 3 / 4));
        $verifier = Base64Url::encode($bytes);

        // Trim to exact length
        return substr($verifier, 0, $length);
    }

    /**
     * Generate code challenge from verifier
     *
     * @param string $code_verifier The code verifier
     * @param string $method Challenge method ('S256' or 'plain')
     * @return string Code challenge
     * @throws \InvalidArgumentException If verifier or method is invalid
     */
    public static function generateChallenge(string $code_verifier, string $method = 'S256'): string
    {
        if (!self::validateVerifier($code_verifier)) {
            throw new \InvalidArgumentException('Invalid code verifier format');
        }

        if (!self::validateMethod($method)) {
            throw new \InvalidArgumentException('Invalid code challenge method');
        }

        if ($method === 'S256') {
            $hash = hash('sha256', $code_verifier, true);
            return Base64Url::encode($hash);
        }

        // 'plain' method: challenge = verifier
        return $code_verifier;
    }

    /**
     * Verify code challenge matches verifier
     *
     * @param string $code_verifier Code verifier from client
     * @param string $code_challenge Stored code challenge
     * @param string $method Challenge method used ('S256' or 'plain')
     * @return bool True if verification succeeds
     */
    public static function verify(
        string $code_verifier,
        string $code_challenge,
        string $method = 'S256'
    ): bool {
        if (!self::validateVerifier($code_verifier)) {
            return false;
        }

        if (!self::validateMethod($method)) {
            return false;
        }

        $computed_challenge = self::generateChallenge($code_verifier, $method);

        // Timing-safe comparison to prevent timing attacks
        return hash_equals($code_challenge, $computed_challenge);
    }

    /**
     * Validate code verifier format
     *
     * Per RFC 7636: Must be 43-128 characters from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
     *
     * @param string $code_verifier Code verifier to validate
     * @return bool True if valid
     */
    public static function validateVerifier(string $code_verifier): bool
    {
        $length = strlen($code_verifier);

        if ($length < self::MIN_VERIFIER_LENGTH || $length > self::MAX_VERIFIER_LENGTH) {
            return false;
        }

        return preg_match('/^[A-Za-z0-9\-._~]+$/', $code_verifier) === 1;
    }

    /**
     * Validate code challenge method
     *
     * @param string $method Method to validate
     * @return bool True if valid
     */
    public static function validateMethod(string $method): bool
    {
        return in_array($method, self::SUPPORTED_METHODS, true);
    }

    /**
     * Get supported challenge methods
     *
     * @return array Supported methods
     */
    public static function getSupportedMethods(): array
    {
        return self::SUPPORTED_METHODS;
    }

    /**
     * Generate verifier and challenge pair
     *
     * @param string $method Challenge method ('S256' or 'plain')
     * @return array{verifier: string, challenge: string, method: string}
     * @throws \InvalidArgumentException If method is invalid
     */
    public static function generatePair(string $method = 'S256'): array
    {
        if (!self::validateMethod($method)) {
            throw new \InvalidArgumentException('Invalid code challenge method');
        }

        $verifier = self::generateVerifier();
        $challenge = self::generateChallenge($verifier, $method);

        return [
            'verifier'  => $verifier,
            'challenge' => $challenge,
            'method'    => $method,
        ];
    }

    /**
     * Check if PKCE is required based on client type
     *
     * @param bool $is_public_client True if public client (SPA, mobile app)
     * @return bool True if PKCE should be required
     */
    public static function isRequired(bool $is_public_client): bool
    {
        // PKCE is strongly recommended for public clients
        return $is_public_client;
    }

    /**
     * Validate PKCE parameters from authorization request
     *
     * @param string|null $code_challenge Code challenge from request
     * @param string|null $code_challenge_method Challenge method from request
     * @param bool $require_pkce Whether PKCE is required
     * @return array{valid: bool, error: string|null}
     */
    public static function validateAuthorizationRequest(
        ?string $code_challenge,
        ?string $code_challenge_method,
        bool $require_pkce = false
    ): array {
        // If PKCE not provided
        if (empty($code_challenge)) {
            if ($require_pkce) {
                return [
                    'valid' => false,
                    'error' => 'code_challenge is required for this client',
                ];
            }
            return ['valid' => true, 'error' => null];
        }

        // Validate method
        $method = $code_challenge_method ?? 'plain';
        if (!self::validateMethod($method)) {
            return [
                'valid' => false,
                'error' => 'invalid code_challenge_method',
            ];
        }

        // S256 is strongly recommended over plain
        if ($method === 'plain') {
            // You might want to reject 'plain' in production
            // return ['valid' => false, 'error' => 'S256 method required'];
        }

        return ['valid' => true, 'error' => null];
    }
}

<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\JWT;

/**
 * JWT Encoder/Decoder
 *
 * Handles JWT token encoding and decoding using HS256 algorithm.
 * Implements RFC 7519 (JSON Web Token) and RFC 7515 (JSON Web Signature).
 *
 * @package WPRestAuth\AuthToolkit\JWT
 */
class Encoder
{
    private string $secret;
    private string $algorithm = 'HS256';

    public function __construct(string $secret)
    {
        if (empty($secret)) {
            throw new \InvalidArgumentException('JWT secret cannot be empty');
        }
        $this->secret = $secret;
    }

    /**
     * Encode a JWT token
     *
     * @param array $claims JWT claims to encode
     * @return string JWT token
     */
    public function encode(array $claims): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->algorithm,
        ];

        $segments = [
            Base64Url::encode(json_encode($header)),
            Base64Url::encode(json_encode($claims)),
        ];

        $signing_input = implode('.', $segments);
        $signature = hash_hmac('sha256', $signing_input, $this->secret, true);
        $segments[] = Base64Url::encode($signature);

        return implode('.', $segments);
    }

    /**
     * Decode a JWT token
     *
     * @param string $jwt JWT token to decode
     * @return array|false Decoded payload or false on failure
     */
    public function decode(string $jwt)
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            return false;
        }

        [$header64, $payload64, $signature64] = $segments;

        $header = json_decode(Base64Url::decode($header64), true);
        $payload = json_decode(Base64Url::decode($payload64), true);
        $signature = Base64Url::decode($signature64);

        if (!$header || !$payload || !$signature) {
            return false;
        }

        // Verify algorithm
        if (!isset($header['alg']) || $header['alg'] !== $this->algorithm) {
            return false;
        }

        // Verify signature
        $signing_input = $header64 . '.' . $payload64;
        $expected_signature = hash_hmac('sha256', $signing_input, $this->secret, true);

        if (!hash_equals($expected_signature, $signature)) {
            return false;
        }

        // Check expiration
        if (isset($payload['exp']) && time() >= $payload['exp']) {
            return false;
        }

        return $payload;
    }

    /**
     * Verify JWT signature without decoding
     *
     * @param string $jwt JWT token to verify
     * @return bool True if signature is valid
     */
    public function verify(string $jwt): bool
    {
        return $this->decode($jwt) !== false;
    }
}

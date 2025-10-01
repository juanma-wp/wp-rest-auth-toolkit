<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\JWT;

/**
 * Base64URL Encoder/Decoder
 *
 * Implements Base64URL encoding per RFC 7515 (JSON Web Signature).
 * Base64URL is base64 encoding with URL-safe characters:
 * - '+' becomes '-'
 * - '/' becomes '_'
 * - Padding '=' is removed
 *
 * @package WPRestAuth\AuthToolkit\JWT
 */
class Base64Url
{
    /**
     * Base64URL encode
     *
     * @param string $data Data to encode
     * @return string Base64URL encoded string
     */
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode
     *
     * @param string $data Data to decode
     * @return string Decoded string
     */
    public static function decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}

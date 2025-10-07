<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Security;

/**
 * IP Address Resolver
 *
 * Resolves client IP addresses with proxy/load balancer awareness.
 * Checks multiple headers in order of reliability and validates IPs
 * to prevent private/reserved range spoofing.
 *
 * @package WPRestAuth\AuthToolkit\Security
 */
class IpResolver
{
    /**
     * Headers to check for client IP (in order of preference)
     */
    private const IP_HEADERS = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    ];

    /**
     * Get client IP address
     *
     * @return string Client IP address (IPv4 or IPv6)
     */
    public static function get(): string
    {
        foreach (self::IP_HEADERS as $header) {
            if (!array_key_exists($header, $_SERVER) || empty($_SERVER[$header])) {
                continue;
            }

            // X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2)
            // We want the first (original client) IP
            $ip = self::sanitize($_SERVER[$header]);
            $ip = explode(',', $ip)[0];
            $ip = trim($ip);

            // Validate IP and ensure it's not from private/reserved ranges
            if (self::isValidPublicIp($ip)) {
                return $ip;
            }
        }

        // Fallback to REMOTE_ADDR or default
        $fallback = isset($_SERVER['REMOTE_ADDR']) ? self::sanitize($_SERVER['REMOTE_ADDR']) : '0.0.0.0';

        // In CLI/test environments, loopback IPs are common - return non-routable default
        if (in_array($fallback, ['127.0.0.1', '::1'], true)) {
            return '0.0.0.0';
        }

        return $fallback;
    }

    /**
     * Check if IP is valid and public (not private/reserved)
     *
     * @param string $ip IP address to validate
     * @return bool True if valid public IP
     */
    private static function isValidPublicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }

    /**
     * Sanitize IP address input
     *
     * @param string $ip Raw IP address
     * @return string Sanitized IP
     */
    private static function sanitize(string $ip): string
    {
        // Remove any whitespace
        $ip = trim($ip);

        // For WordPress environments, use sanitize_text_field if available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field($ip);
        }

        // Basic sanitization: remove control characters and strip tags
        return htmlspecialchars(strip_tags($ip), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Check if IP is from localhost/loopback
     *
     * @param string|null $ip IP address (null = auto-detect)
     * @return bool True if localhost
     */
    public static function isLocalhost(?string $ip = null): bool
    {
        $ip = $ip ?? self::get();
        return in_array($ip, ['127.0.0.1', '::1', '0.0.0.0'], true);
    }

    /**
     * Check if IP is IPv6
     *
     * @param string|null $ip IP address (null = auto-detect)
     * @return bool True if IPv6
     */
    public static function isIpv6(?string $ip = null): bool
    {
        $ip = $ip ?? self::get();
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Get IP from specific header (for testing/debugging)
     *
     * @param string $header Header name
     * @return string|null IP address or null if not found
     */
    public static function getFromHeader(string $header): ?string
    {
        if (!isset($_SERVER[$header])) {
            return null;
        }

        $ip = self::sanitize($_SERVER[$header]);
        $ip = explode(',', $ip)[0];
        return trim($ip);
    }
}

<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Http;

/**
 * HTTP Cookie Manager
 *
 * Manages HTTP-only cookies for refresh token storage with secure defaults.
 * Supports both PHP 7.3+ array syntax and legacy string syntax for SameSite attribute.
 *
 * @package WPRestAuth\AuthToolkit\Http
 */
class Cookie
{
    /**
     * Set an HTTP-only cookie with secure defaults
     *
     * @param string $name Cookie name
     * @param string $value Cookie value
     * @param array $options Cookie options
     * @return bool Success status
     */
    public static function set(string $name, string $value, array $options = []): bool
    {
        // Skip in CLI/test environments
        if (self::isCliEnvironment()) {
            return true;
        }

        $defaults = [
            'expires'  => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => self::isSecure(),
            'httponly' => true,
            'samesite' => 'Strict',
        ];

        $options = array_merge($defaults, $options);

        // Apply WordPress filters if available
        if (function_exists('apply_filters')) {
            $options['samesite'] = apply_filters('wp_rest_auth_cookie_samesite', $options['samesite']);
        }

        // TO-DO: Set PHP 8.1 as the minimal version for this plugin and remove this
        // extra code (just return one setcookie)

        // Use PHP 7.3+ array syntax if available
        if (PHP_VERSION_ID >= 70300) {
            return setcookie($name, $value, [
                'expires'  => $options['expires'],
                'path'     => $options['path'],
                'domain'   => $options['domain'],
                'secure'   => $options['secure'],
                'httponly' => $options['httponly'],
                'samesite' => $options['samesite'],
            ]);
        }

        // Fallback for PHP < 7.3: use path hack for SameSite
        return setcookie(
            $name,
            $value,
            $options['expires'],
            $options['path'] . '; SameSite=' . $options['samesite'],
            $options['domain'],
            $options['secure'],
            $options['httponly']
        );
    }

    /**
     * Delete a cookie
     *
     * @param string $name Cookie name
     * @param string $path Cookie path
     * @return bool Success status
     */
    public static function delete(string $name, string $path = '/'): bool
    {
        // TO-DO: Check - how is this deleting the cookie?

        return self::set($name, '', [
            'expires' => time() - 3600,
            'path'    => $path,
        ]);
    }

    /**
     * Get cookie value
     *
     * Handles both standard $_COOKIE access and fallback parsing from HTTP_COOKIE header
     * for cases where $_COOKIE is not populated (e.g., some cross-origin REST API requests).
     *
     * @param string $name Cookie name
     * @param mixed $default Default value if cookie doesn't exist
     * @return mixed Cookie value or default
     */
    public static function get(string $name, $default = null)
    {
        // Try $_COOKIE first (standard approach)
        if (isset($_COOKIE[$name])) {
            $value = function_exists('wp_unslash') ? wp_unslash($_COOKIE[$name]) : stripslashes($_COOKIE[$name]);
        } elseif (!empty($_SERVER['HTTP_COOKIE'])) {
            // Fallback: parse from HTTP_COOKIE header
            // This handles cases where $_COOKIE isn't populated in cross-origin REST requests
            $cookies = [];
            $http_cookie = function_exists('wp_unslash') ? wp_unslash($_SERVER['HTTP_COOKIE']) : stripslashes($_SERVER['HTTP_COOKIE']);
            parse_str(str_replace('; ', '&', $http_cookie), $cookies);

            if (!isset($cookies[$name])) {
                return $default;
            }

            $value = $cookies[$name];
        } else {
            return $default;
        }


        // TO-DO: Set PHP 8.1 as minimal version so unify this code

        // Use WordPress sanitization if available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field($value);
        }

        // Fallback sanitization (FILTER_SANITIZE_STRING is deprecated in PHP 8.1+)
        $strip_func = function_exists('wp_strip_all_tags') ? 'wp_strip_all_tags' : 'strip_tags';
        return htmlspecialchars($strip_func($value), ENT_QUOTES, 'UTF-8');
    }

    /**
     * Check if cookie exists
     *
     * @param string $name Cookie name
     * @return bool True if cookie exists
     */
    public static function has(string $name): bool
    {
        return isset($_COOKIE[$name]);
    }

    /**
     * Check if request is over HTTPS
     *
     * @return bool True if secure
     */
    private static function isSecure(): bool
    {
        // Check WordPress function first
        if (function_exists('is_ssl')) {
            return is_ssl();
        }

        // TO-DO: Double check these verifications

        // Standard HTTPS detection
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }

        // Check if behind proxy/load balancer
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
            return true;
        }

        if (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
            return true;
        }

        return false;
    }

    /**
     * Check if running in CLI environment
     *
     * Determines if code is running in a true CLI context (terminal commands)
     * vs a web request that happens to be processed by PHP-CLI (WordPress Studio, etc.)
     *
     * @return bool True if CLI
     */
    private static function isCliEnvironment(): bool
    {
        // TO-DO: Double check this

        // PHPUnit test environment - skip cookies to avoid "headers already sent" errors
        if (defined('PHPUNIT_COMPOSER_INSTALL') || defined('WP_TESTS_CONFIG_FILE_PATH')) {
            return true;
        }

        // If HTTP_HOST is set, this is a web request regardless of SAPI
        // WordPress Studio and similar tools use PHP-CLI to serve web requests
        if (isset($_SERVER['HTTP_HOST']) || isset($_SERVER['REQUEST_URI'])) {
            return false;
        }

        // Check for WP-CLI command execution (without HTTP context)
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        // Check SAPI (but only if no HTTP context)
        if (php_sapi_name() === 'cli') {
            return true;
        }

        return false;
    }

    /**
     * Set refresh token cookie with sensible defaults
     *
     * @param string $name Cookie name
     * @param string $value Refresh token value
     * @param int $ttl Time to live in seconds
     * @param string $path Cookie path
     * @return bool Success status
     */
    public static function setRefreshToken(
        string $name,
        string $value,
        int $ttl = 2592000,
        string $path = '/'
    ): bool {
        // TO-DO: Check if src/Token/RefreshTokenManager.php should handle
        // the creation of the refresh token

        return self::set($name, $value, [
            'expires'  => time() + $ttl,
            'path'     => $path,
            'httponly' => true,
            'secure'   => true,
            'samesite' => 'Strict',
        ]);
    }
}

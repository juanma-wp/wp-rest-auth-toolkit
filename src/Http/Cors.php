<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Http;

/**
 * CORS (Cross-Origin Resource Sharing) Handler
 *
 * Manages CORS headers for cross-origin API requests.
 * Supports origin validation, preflight requests, and credential handling.
 *
 * @package WPRestAuth\AuthToolkit\Http
 */
class Cors
{
    /**
     * Handle CORS request and add appropriate headers
     *
     * @param array|string $allowed_origins Allowed origins (array or newline-separated string)
     * @param array $options Additional CORS options
     * @return void
     */
    public static function handleRequest($allowed_origins, array $options = []): void
    {
        $origin = self::getOrigin();

        if (empty($origin)) {
            return;
        }

        // Parse allowed origins
        $allowed_list = self::parseOrigins($allowed_origins);

        if (!self::isOriginAllowed($origin, $allowed_list)) {
            return;
        }

        // Set CORS headers
        self::setHeaders($origin, $options);

        // Handle preflight OPTIONS request
        if (self::isPreflightRequest()) {
            self::handlePreflight();
        }
    }

    /**
     * Set CORS headers
     *
     * @param string $origin Allowed origin
     * @param array $options CORS options
     * @return void
     */
    private static function setHeaders(string $origin, array $options): void
    {
        $defaults = [
            'credentials' => true,
            'methods'     => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
            'headers'     => ['Authorization', 'Content-Type', 'X-Requested-With', 'X-WP-Nonce'],
            'max_age'     => 86400, // 24 hours
        ];

        $options = array_merge($defaults, $options);

        header('Access-Control-Allow-Origin: ' . $origin);

        if ($options['credentials']) {
            header('Access-Control-Allow-Credentials: true');
        }

        header('Access-Control-Allow-Methods: ' . implode(', ', $options['methods']));
        header('Access-Control-Allow-Headers: ' . implode(', ', $options['headers']));
        header('Access-Control-Max-Age: ' . $options['max_age']);
    }

    /**
     * Handle preflight OPTIONS request
     *
     * @return void
     */
    private static function handlePreflight(): void
    {
        http_response_code(200);
        exit;
    }

    /**
     * Check if request is a preflight request
     *
     * @return bool True if preflight
     */
    private static function isPreflightRequest(): bool
    {
        return isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS';
    }

    /**
     * Get origin from request
     *
     * @return string Origin URL or empty string
     */
    private static function getOrigin(): string
    {
        if (!isset($_SERVER['HTTP_ORIGIN'])) {
            return '';
        }

        $origin = function_exists('wp_unslash') ? wp_unslash($_SERVER['HTTP_ORIGIN']) : stripslashes($_SERVER['HTTP_ORIGIN']);

        // Sanitize if WordPress function available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field($origin);
        }

        return filter_var($origin, FILTER_SANITIZE_URL);
    }

    /**
     * Parse allowed origins from various formats
     *
     * @param array|string $origins Allowed origins
     * @return array Parsed origins list
     */
    private static function parseOrigins($origins): array
    {
        if (is_array($origins)) {
            return array_map('trim', $origins);
        }

        if (is_string($origins)) {
            return array_map('trim', explode("\n", $origins));
        }

        return [];
    }

    /**
     * Check if origin is allowed
     *
     * @param string $origin Request origin
     * @param array $allowed_list Allowed origins list
     * @return bool True if allowed
     */
    private static function isOriginAllowed(string $origin, array $allowed_list): bool
    {
        // Empty list = deny all
        if (empty($allowed_list)) {
            return false;
        }

        // Wildcard allows all
        if (in_array('*', $allowed_list, true)) {
            return true;
        }

        // Exact match
        if (in_array($origin, $allowed_list, true)) {
            return true;
        }

        // Pattern matching (e.g., *.example.com)
        foreach ($allowed_list as $allowed) {
            if (self::matchesPattern($origin, $allowed)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if origin matches pattern
     *
     * @param string $origin Request origin
     * @param string $pattern Allowed pattern
     * @return bool True if matches
     */
    private static function matchesPattern(string $origin, string $pattern): bool
    {
        // Convert wildcard pattern to regex
        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace(['*', '.'], ['.*', '\.'], $pattern) . '$/';
            return preg_match($regex, $origin) === 1;
        }

        return false;
    }

    /**
     * Add CORS support for WordPress REST API
     *
     * @param array|string $allowed_origins Allowed origins
     * @return void
     */
    public static function enableForWordPress($allowed_origins): void
    {
        add_action('rest_api_init', function () use ($allowed_origins) {
            self::handleRequest($allowed_origins);
        });
    }

    /**
     * Check if origin is localhost (for development)
     *
     * @param string|null $origin Origin to check (null = auto-detect)
     * @return bool True if localhost
     */
    public static function isLocalhost(?string $origin = null): bool
    {
        $origin = $origin ?? self::getOrigin();

        $localhost_patterns = [
            'http://localhost',
            'https://localhost',
            'http://127.0.0.1',
            'https://127.0.0.1',
        ];

        foreach ($localhost_patterns as $pattern) {
            if (strpos($origin, $pattern) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get allowed origins from WordPress options
     *
     * @param string $option_key Option key in WordPress
     * @param string $default Default value
     * @return array Allowed origins
     */
    public static function getFromWordPressOption(string $option_key, string $default = ''): array
    {
        if (!function_exists('get_option')) {
            return self::parseOrigins($default);
        }

        $origins = get_option($option_key, $default);
        return self::parseOrigins($origins);
    }
}

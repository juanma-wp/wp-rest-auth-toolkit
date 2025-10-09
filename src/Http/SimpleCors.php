<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Http;

/**
 * Simple CORS Handler for WordPress REST API
 *
 * A simplified approach to CORS handling inspired by popular WordPress plugins.
 * This class provides a maintainable solution that works with WordPress's
 * REST API infrastructure.
 *
 * @package WPRestAuth\AuthToolkit\Http
 */
class SimpleCors
{
    /**
     * Enable CORS support for REST API
     *
     * @param string|array $allowed_origins Allowed origins (string with newlines or array)
     * @param array $options Additional options (credentials, methods, headers)
     * @return void
     */
    public static function enable($allowed_origins = '*', array $options = []): void
    {
        $defaults = [
            'credentials' => true,
            'methods'     => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
            'headers'     => ['Authorization', 'Content-Type', 'X-WP-Nonce', 'X-Requested-With'],
            'max_age'     => 86400, // 24 hours
        ];

        $options = array_merge($defaults, $options);

        // Parse allowed origins
        $origins = self::parseOrigins($allowed_origins);

        // Hook into REST API to add CORS headers
        add_action('rest_api_init', function() use ($origins, $options) {
            // Remove WordPress default CORS handlers
            remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');

            // Add our CORS headers
            add_filter('rest_pre_serve_request', function($served) use ($origins, $options) {
                self::sendHeaders($origins, $options);
                return $served;
            });
        });

        // Handle preflight requests early
        add_action('init', function() use ($origins, $options) {
            if (self::isRestRequest() && self::isPreflight()) {
                self::sendHeaders($origins, $options);
                exit;
            }
        });
    }

    /**
     * Send CORS headers
     *
     * @param array $origins Allowed origins
     * @param array $options CORS options
     * @return void
     */
    private static function sendHeaders(array $origins, array $options): void
    {
        $request_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        // Check if origin is allowed
        if (empty($request_origin)) {
            return;
        }

        // Handle wildcard
        if (in_array('*', $origins, true)) {
            header('Access-Control-Allow-Origin: *');
        } elseif (in_array($request_origin, $origins, true)) {
            header('Access-Control-Allow-Origin: ' . $request_origin);

            if ($options['credentials']) {
                header('Access-Control-Allow-Credentials: true');
            }
        } else {
            // Origin not allowed
            return;
        }

        // Set other CORS headers
        header('Access-Control-Allow-Methods: ' . implode(', ', $options['methods']));
        header('Access-Control-Allow-Headers: ' . implode(', ', $options['headers']));
        header('Access-Control-Max-Age: ' . $options['max_age']);
        header('Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link');
    }

    /**
     * Parse origins from various formats
     *
     * @param string|array $origins Origins in various formats
     * @return array Parsed origins
     */
    private static function parseOrigins($origins): array
    {
        if ($origins === '*') {
            return ['*'];
        }

        if (is_array($origins)) {
            return array_map('trim', $origins);
        }

        // String with newlines
        $lines = explode("\n", $origins);
        $parsed = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if (!empty($line)) {
                $parsed[] = $line;
            }
        }

        return $parsed;
    }

    /**
     * Check if this is a REST API request
     *
     * @return bool
     */
    private static function isRestRequest(): bool
    {
        // Check if REST_REQUEST constant is defined
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        // Check request URI
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        // Check for common REST API patterns
        // We can't use rest_get_url_prefix() here as it might not be available yet
        return strpos($request_uri, '/wp-json/') !== false;
    }

    /**
     * Check if this is a preflight request
     *
     * @return bool
     */
    private static function isPreflight(): bool
    {
        return isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS';
    }
}
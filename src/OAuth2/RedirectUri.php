<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\OAuth2;

/**
 * OAuth2 Redirect URI Validator
 *
 * Validates and matches OAuth2 redirect URIs per RFC 6749.
 * Ensures secure redirect URI handling to prevent open redirect vulnerabilities.
 *
 * @package WPRestAuth\AuthToolkit\OAuth2
 */
class RedirectUri
{
    /**
     * Validate redirect URI format and security
     *
     * @param string $uri URI to validate
     * @param bool $allow_localhost Allow localhost for development
     * @return bool True if valid
     */
    public static function validate(string $uri, bool $allow_localhost = true): bool
    {
        $parse_func = function_exists('wp_parse_url') ? 'wp_parse_url' : 'parse_url';
        $parsed = $parse_func($uri);

        // Must have scheme and host
        if (!isset($parsed['scheme']) || !isset($parsed['host'])) {
            return false;
        }

        // Validate scheme
        if (!in_array($parsed['scheme'], ['https', 'http'], true)) {
            // Allow custom schemes for mobile apps (e.g., myapp://)
            if (!self::isCustomScheme($parsed['scheme'])) {
                return false;
            }
        }

        // Check localhost rules
        if (self::isLocalhost($parsed['host'])) {
            if (!$allow_localhost) {
                return false;
            }
            // Allow HTTP for localhost
            return in_array($parsed['scheme'], ['http', 'https'], true);
        }

        // Production URLs must use HTTPS
        if ($parsed['scheme'] !== 'https' && !self::isCustomScheme($parsed['scheme'])) {
            return false;
        }

        // Fragment identifier (#) is not allowed (RFC 6749)
        if (isset($parsed['fragment'])) {
            return false;
        }

        return true;
    }

    /**
     * Check if URIs match exactly
     *
     * @param string $uri1 First URI
     * @param string $uri2 Second URI
     * @return bool True if exact match
     */
    public static function exactMatch(string $uri1, string $uri2): bool
    {
        return $uri1 === $uri2;
    }

    /**
     * Check if redirect URI matches registered URI
     *
     * Supports exact matching and wildcard subdomain matching.
     *
     * @param string $redirect_uri Requested redirect URI
     * @param array $registered_uris Registered redirect URIs
     * @param bool $allow_wildcards Allow wildcard matching
     * @return bool True if matches
     */
    public static function matches(
        string $redirect_uri,
        array $registered_uris,
        bool $allow_wildcards = false
    ): bool {
        foreach ($registered_uris as $registered) {
            // Exact match
            if (self::exactMatch($redirect_uri, $registered)) {
                return true;
            }

            // Wildcard matching (if enabled)
            if ($allow_wildcards && self::wildcardMatch($redirect_uri, $registered)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Wildcard subdomain matching
     *
     * Allows patterns like https://*.example.com/callback
     *
     * @param string $uri URI to test
     * @param string $pattern Pattern with wildcards
     * @return bool True if matches
     */
    private static function wildcardMatch(string $uri, string $pattern): bool
    {
        if (strpos($pattern, '*') === false) {
            return false;
        }

        // Convert pattern to regex
        $regex = preg_quote($pattern, '/');
        $regex = str_replace('\*', '.*', $regex);
        $regex = '/^' . $regex . '$/';

        return preg_match($regex, $uri) === 1;
    }

    /**
     * Check if host is localhost
     *
     * @param string $host Hostname
     * @return bool True if localhost
     */
    private static function isLocalhost(string $host): bool
    {
        $localhost_patterns = [
            'localhost',
            '127.0.0.1',
            '::1',
            '0.0.0.0',
        ];

        // Exact match
        if (in_array($host, $localhost_patterns, true)) {
            return true;
        }

        // Match 127.x.x.x
        if (strpos($host, '127.') === 0) {
            return true;
        }

        // Match localhost with port
        if (strpos($host, 'localhost:') === 0) {
            return true;
        }

        return false;
    }

    /**
     * Check if scheme is a custom mobile app scheme
     *
     * @param string $scheme URI scheme
     * @return bool True if custom scheme
     */
    private static function isCustomScheme(string $scheme): bool
    {
        // Custom schemes are typically lowercase alphanumeric
        // and not http/https/ftp/etc.
        $standard_schemes = ['http', 'https', 'ftp', 'file', 'data'];

        if (in_array($scheme, $standard_schemes, true)) {
            return false;
        }

        // Must be alphanumeric
        return preg_match('/^[a-z0-9]+$/', $scheme) === 1;
    }

    /**
     * Extract query parameters from URI
     *
     * @param string $uri URI to parse
     * @return array Query parameters
     */
    public static function getQueryParams(string $uri): array
    {
        $parse_func = function_exists('wp_parse_url') ? 'wp_parse_url' : 'parse_url';
        $parsed = $parse_func($uri);
        $params = [];

        if (isset($parsed['query'])) {
            parse_str($parsed['query'], $params);
        }

        return $params;
    }

    /**
     * Append query parameters to URI
     *
     * @param string $uri Base URI
     * @param array $params Parameters to append
     * @return string URI with parameters
     */
    public static function appendParams(string $uri, array $params): string
    {
        if (empty($params)) {
            return $uri;
        }

        $separator = strpos($uri, '?') === false ? '?' : '&';
        return $uri . $separator . http_build_query($params);
    }

    /**
     * Build authorization callback URI with parameters
     *
     * @param string $redirect_uri Base redirect URI
     * @param string $code Authorization code
     * @param string|null $state State parameter
     * @return string Callback URI
     */
    public static function buildAuthorizationCallback(
        string $redirect_uri,
        string $code,
        ?string $state = null
    ): string {
        $params = ['code' => $code];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::appendParams($redirect_uri, $params);
    }

    /**
     * Build error callback URI
     *
     * @param string $redirect_uri Base redirect URI
     * @param string $error Error code
     * @param string|null $error_description Error description
     * @param string|null $state State parameter
     * @return string Error callback URI
     */
    public static function buildErrorCallback(
        string $redirect_uri,
        string $error,
        ?string $error_description = null,
        ?string $state = null
    ): string {
        $params = ['error' => $error];

        if ($error_description !== null) {
            $params['error_description'] = $error_description;
        }

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::appendParams($redirect_uri, $params);
    }

    /**
     * Sanitize redirect URI
     *
     * @param string $uri URI to sanitize
     * @return string Sanitized URI
     */
    public static function sanitize(string $uri): string
    {
        // Use WordPress sanitization if available
        if (function_exists('esc_url_raw')) {
            return esc_url_raw($uri);
        }

        return filter_var($uri, FILTER_SANITIZE_URL);
    }

    /**
     * Normalize redirect URI (remove default ports, lowercase host)
     *
     * @param string $uri URI to normalize
     * @return string Normalized URI
     */
    public static function normalize(string $uri): string
    {
        $parse_func = function_exists('wp_parse_url') ? 'wp_parse_url' : 'parse_url';
        $parsed = $parse_func($uri);

        if (!$parsed) {
            return $uri;
        }

        // Lowercase host
        if (isset($parsed['host'])) {
            $parsed['host'] = strtolower($parsed['host']);
        }

        // Remove default ports
        if (isset($parsed['port'])) {
            $is_default_port = (
                ($parsed['scheme'] === 'http' && $parsed['port'] === 80) ||
                ($parsed['scheme'] === 'https' && $parsed['port'] === 443)
            );

            if ($is_default_port) {
                unset($parsed['port']);
            }
        }

        return self::buildFromParts($parsed);
    }

    /**
     * Build URI from parsed components
     *
     * @param array $parts Parsed URL components
     * @return string Rebuilt URI
     */
    private static function buildFromParts(array $parts): string
    {
        $uri = '';

        if (isset($parts['scheme'])) {
            $uri .= $parts['scheme'] . '://';
        }

        if (isset($parts['user'])) {
            $uri .= $parts['user'];
            if (isset($parts['pass'])) {
                $uri .= ':' . $parts['pass'];
            }
            $uri .= '@';
        }

        if (isset($parts['host'])) {
            $uri .= $parts['host'];
        }

        if (isset($parts['port'])) {
            $uri .= ':' . $parts['port'];
        }

        if (isset($parts['path'])) {
            $uri .= $parts['path'];
        }

        if (isset($parts['query'])) {
            $uri .= '?' . $parts['query'];
        }

        if (isset($parts['fragment'])) {
            $uri .= '#' . $parts['fragment'];
        }

        return $uri;
    }
}

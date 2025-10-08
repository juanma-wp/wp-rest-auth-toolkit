<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Http;

/**
 * Cookie Configuration Manager
 *
 * Provides environment-aware cookie configuration for authentication tokens.
 * Automatically adjusts cookie security settings based on environment (development/staging/production)
 * with optional manual overrides via WordPress admin settings or constants.
 *
 * Priority order:
 * 1. Constants (defined in wp-config.php)
 * 2. Filters (programmatic control)
 * 3. Saved options (admin panel)
 * 4. Environment-based defaults (if auto-detection enabled)
 * 5. Hard-coded defaults
 *
 * @package WPRestAuth\AuthToolkit\Http
 */
class CookieConfig
{
    /**
     * Environment types
     */
    private const ENV_DEVELOPMENT = 'development';
    private const ENV_STAGING     = 'staging';
    private const ENV_PRODUCTION  = 'production';

    /**
     * Cookie configuration cache
     *
     * @var array<string, mixed>|null
     */
    private static ?array $config_cache = null;

    /**
     * Option name prefix for storing configuration
     * Each plugin should override this via constructor parameter
     *
     * @var string
     */
    private static string $option_prefix = 'wp_rest_auth_cookie_config';

    /**
     * Filter prefix for WordPress hooks
     *
     * @var string
     */
    private static string $filter_prefix = 'wp_rest_auth_cookie';

    /**
     * Constant prefix for wp-config.php constants
     *
     * @var string
     */
    private static string $constant_prefix = 'WP_REST_AUTH_COOKIE';

    /**
     * Get cookie configuration for current environment
     *
     * @param string $option_name   Option name for storing config (default: 'wp_rest_auth_cookie_config')
     * @param string $filter_prefix Filter prefix for hooks (default: 'wp_rest_auth_cookie')
     * @param string $constant_prefix Constant prefix (default: 'WP_REST_AUTH_COOKIE')
     * @return array{
     *     enabled: bool,
     *     name: string,
     *     samesite: string,
     *     secure: bool,
     *     path: string,
     *     domain: string,
     *     httponly: bool,
     *     lifetime: int,
     *     environment: string,
     *     auto_detect: bool
     * }
     */
    public static function getConfig(
        string $option_name = 'wp_rest_auth_cookie_config',
        string $filter_prefix = 'wp_rest_auth_cookie',
        string $constant_prefix = 'WP_REST_AUTH_COOKIE'
    ): array {
        // Use cache key based on option name
        $cache_key = md5($option_name);

        if (null !== self::$config_cache && isset(self::$config_cache[$cache_key])) {
            return self::$config_cache[$cache_key];
        }

        // Set prefixes for this call
        self::$option_prefix   = $option_name;
        self::$filter_prefix   = $filter_prefix;
        self::$constant_prefix = $constant_prefix;

        $saved_config = self::getSavedConfig();
        $auto_detect  = self::isAutoDetectEnabled($saved_config);
        $environment  = self::detectEnvironment();

        // Start with base defaults
        $config = self::getBaseDefaults();

        // Apply environment-based defaults if auto-detection is enabled
        if ($auto_detect) {
            $config = array_merge($config, self::getEnvironmentDefaults($environment));
        }

        // Apply saved options from admin panel
        $config = array_merge($config, self::applySavedConfig($saved_config));

        // Apply constants (highest priority after filters)
        $config = self::applyConstants($config);

        // Add metadata
        $config['environment'] = $environment;
        $config['auto_detect'] = $auto_detect;

        // Apply global filter
        if (function_exists('apply_filters')) {
            $config = apply_filters("{$filter_prefix}_config", $config);
        }

        // Apply individual field filters
        foreach ($config as $key => $value) {
            if (function_exists('apply_filters')) {
                $config[$key] = apply_filters("{$filter_prefix}_{$key}", $value, $config);
            }
        }

        // Final validation
        $config = self::validateConfig($config);

        // Cache the result
        if (!is_array(self::$config_cache)) {
            self::$config_cache = [];
        }
        self::$config_cache[$cache_key] = $config;

        // Debug logging if enabled
        self::maybeLogConfig($config);

        return $config;
    }

    /**
     * Get base default configuration values
     *
     * @return array<string, mixed>
     */
    private static function getBaseDefaults(): array
    {
        $default_lifetime = defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400;

        return [
            'enabled'  => true,
            'name'     => 'auth_session',
            'samesite' => 'Lax',
            'secure'   => true,
            'path'     => '/',
            'domain'   => '',
            'httponly' => true,
            'lifetime' => $default_lifetime,
        ];
    }

    /**
     * Get environment-specific default configuration
     *
     * @param string $environment Current environment
     * @return array<string, mixed>
     */
    private static function getEnvironmentDefaults(string $environment): array
    {
        $defaults = [];

        switch ($environment) {
            case self::ENV_DEVELOPMENT:
                $defaults = [
                    'secure'   => self::isSecure(), // Use actual HTTPS status, but allow HTTP on localhost
                    'samesite' => 'None',   // Allow cross-origin for SPAs
                    'path'     => '/',
                ];
                break;

            case self::ENV_STAGING:
                $defaults = [
                    'secure'   => true,
                    'samesite' => 'Lax', // Relaxed for testing
                    'path'     => '/',
                ];
                break;

            case self::ENV_PRODUCTION:
                $defaults = [
                    'secure'   => true,
                    'samesite' => 'Strict', // Maximum security
                    'path'     => '/wp-json/',
                ];
                break;
        }

        // Apply filter if available
        if (function_exists('apply_filters')) {
            $defaults = apply_filters(
                self::$filter_prefix . '_environment_defaults',
                $defaults,
                $environment
            );
        }

        return $defaults;
    }

    /**
     * Apply saved configuration from admin panel
     *
     * @param array<string, mixed> $saved_config Saved configuration
     * @return array<string, mixed>
     */
    private static function applySavedConfig(array $saved_config): array
    {
        $config = [];

        if (isset($saved_config['samesite']) && 'auto' !== $saved_config['samesite']) {
            $config['samesite'] = self::validateSameSite($saved_config['samesite']);
        }

        if (isset($saved_config['secure']) && 'auto' !== $saved_config['secure']) {
            $config['secure'] = self::parseBoolean($saved_config['secure']);
        }

        if (isset($saved_config['path']) && 'auto' !== $saved_config['path']) {
            $config['path'] = self::sanitizeTextField($saved_config['path']);
        }

        if (isset($saved_config['domain']) && 'auto' !== $saved_config['domain']) {
            $config['domain'] = self::sanitizeTextField($saved_config['domain']);
        }

        // Only allow httponly override in debug mode
        if (isset($saved_config['httponly']) && self::isDebugMode()) {
            $config['httponly'] = self::parseBoolean($saved_config['httponly']);
        }

        if (isset($saved_config['enabled'])) {
            $config['enabled'] = self::parseBoolean($saved_config['enabled']);
        }

        if (isset($saved_config['name']) && !empty($saved_config['name'])) {
            $config['name'] = self::sanitizeKey($saved_config['name']);
        }

        if (isset($saved_config['lifetime']) && is_numeric($saved_config['lifetime'])) {
            $config['lifetime'] = absint($saved_config['lifetime']);
        }

        return $config;
    }

    /**
     * Apply constants to configuration
     *
     * Constants have higher priority than saved options
     *
     * @param array<string, mixed> $config Current configuration
     * @return array<string, mixed>
     */
    private static function applyConstants(array $config): array
    {
        $constant_map = [
            '_ENABLED'  => 'enabled',
            '_NAME'     => 'name',
            '_SAMESITE' => 'samesite',
            '_SECURE'   => 'secure',
            '_PATH'     => 'path',
            '_DOMAIN'   => 'domain',
            '_HTTPONLY' => 'httponly',
            '_LIFETIME' => 'lifetime',
        ];

        foreach ($constant_map as $suffix => $key) {
            $constant = self::$constant_prefix . $suffix;

            if (defined($constant)) {
                $value = constant($constant);

                // Type conversion based on key
                switch ($key) {
                    case 'enabled':
                    case 'secure':
                    case 'httponly':
                        $config[$key] = self::parseBoolean($value);
                        break;

                    case 'lifetime':
                        $config[$key] = absint($value);
                        break;

                    case 'samesite':
                        $config[$key] = self::validateSameSite((string) $value);
                        break;

                    case 'name':
                        $config[$key] = self::sanitizeKey($value);
                        break;

                    default:
                        $config[$key] = self::sanitizeTextField($value);
                        break;
                }
            }
        }

        return $config;
    }

    /**
     * Validate final configuration
     *
     * @param array<string, mixed> $config Configuration to validate
     * @return array<string, mixed>
     */
    private static function validateConfig(array $config): array
    {
        // SameSite=None requires Secure=true, except on localhost in development
        // Modern browsers allow SameSite=None with Secure=false on localhost
        if ('None' === $config['samesite']) {
            $is_development = self::isDevelopment();
            $http_host = $_SERVER['HTTP_HOST'] ?? '';
            $is_localhost_host = 'localhost' === $http_host ||
                                 0 === strpos($http_host, 'localhost:') ||
                                 '127.0.0.1' === $http_host ||
                                 0 === strpos($http_host, '127.0.0.1:');

            $is_localhost = $is_development && $is_localhost_host;

            // Only force secure=true if not localhost in development
            if (!$is_localhost) {
                $config['secure'] = true;
            }
        }

        // Validate SameSite value
        $config['samesite'] = self::validateSameSite($config['samesite']);

        // Ensure lifetime is positive
        if ($config['lifetime'] <= 0) {
            $default_lifetime = defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400;
            $config['lifetime'] = $default_lifetime;
        }

        // Ensure name is not empty
        if (empty($config['name'])) {
            $config['name'] = 'auth_session';
        }

        return $config;
    }

    /**
     * Check if auto-detection is enabled
     *
     * @param array<string, mixed> $saved_config Saved configuration
     * @return bool
     */
    private static function isAutoDetectEnabled(array $saved_config): bool
    {
        // Check for constant override
        $constant = self::$constant_prefix . '_AUTO_DETECT';
        if (defined($constant)) {
            return (bool) constant($constant);
        }

        // Check saved option (default to true)
        if (isset($saved_config['auto_detect'])) {
            return self::parseBoolean($saved_config['auto_detect']);
        }

        return true;
    }

    /**
     * Parse boolean value from various formats
     *
     * @param mixed $value Value to parse
     * @return bool
     */
    private static function parseBoolean($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_numeric($value)) {
            return (bool) $value;
        }

        if (is_string($value)) {
            $value = strtolower(trim($value));
            return in_array($value, ['1', 'true', 'yes', 'on'], true);
        }

        return false;
    }

    /**
     * Log configuration if debug mode is enabled
     *
     * @param array<string, mixed> $config Configuration to log
     */
    private static function maybeLogConfig(array $config): void
    {
        // Logging is disabled for production - only enable in development if needed
        // Use WordPress do_action() for custom logging instead
        if (!self::isDebugMode()) {
            return;
        }

        // Trigger action for custom logging handlers
        if (function_exists('do_action')) {
            do_action('wp_rest_auth_cookie_config_log', $config);
        }
    }

    /**
     * Detect current environment
     *
     * @return string One of: 'development', 'staging', 'production'
     */
    private static function detectEnvironment(): string
    {
        // Use WordPress environment type if available (WP 5.5+)
        if (function_exists('wp_get_environment_type')) {
            $wp_env = wp_get_environment_type();
            // Normalize 'local' to 'development'
            if ('local' === $wp_env) {
                return self::ENV_DEVELOPMENT;
            }
            // Only return if it matches one of our expected values
            if (in_array($wp_env, [self::ENV_DEVELOPMENT, self::ENV_STAGING, self::ENV_PRODUCTION], true)) {
                return $wp_env;
            }
        }

        // Fallback detection based on domain and WP_DEBUG
        $host = '';
        if (isset($_SERVER['HTTP_HOST'])) {
            $value = function_exists('wp_unslash') ? wp_unslash($_SERVER['HTTP_HOST']) : stripslashes($_SERVER['HTTP_HOST']);
            $host = strtolower(self::sanitizeTextField($value));
        }

        // Development indicators
        if (
            in_array($host, ['localhost', '127.0.0.1', '::1'], true) ||
            substr($host, -6) === '.local' ||
            substr($host, -5) === '.test' ||
            substr($host, -10) === '.localhost' ||
            self::isDebugMode()
        ) {
            return self::ENV_DEVELOPMENT;
        }

        // Staging indicators
        if (
            false !== strpos($host, 'staging') ||
            false !== strpos($host, 'dev') ||
            false !== strpos($host, 'test')
        ) {
            return self::ENV_STAGING;
        }

        return self::ENV_PRODUCTION;
    }

    /**
     * Validate SameSite value
     *
     * @param string $value Value to validate
     * @return string Valid SameSite value
     */
    private static function validateSameSite(string $value): string
    {
        $valid = ['None', 'Lax', 'Strict'];
        return in_array($value, $valid, true) ? $value : 'Strict';
    }

    /**
     * Update cookie configuration
     *
     * @param array<string, mixed> $config New configuration
     * @param string $option_name Option name
     * @return bool True on success, false on failure
     */
    public static function updateConfig(array $config, string $option_name = 'wp_rest_auth_cookie_config'): bool
    {
        self::clearCache(); // Clear all cache

        if (function_exists('update_option')) {
            return update_option($option_name, $config);
        }

        return false;
    }

    /**
     * Get default configuration values for admin panel
     *
     * @return array{
     *     enabled: bool,
     *     name: string,
     *     samesite: string,
     *     secure: string,
     *     path: string,
     *     domain: string,
     *     httponly: bool,
     *     lifetime: int,
     *     auto_detect: bool
     * }
     */
    public static function getDefaults(): array
    {
        $default_lifetime = defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400;

        return [
            'enabled'     => true,
            'name'        => 'auth_session',
            'samesite'    => 'auto',
            'secure'      => 'auto',
            'path'        => 'auto',
            'domain'      => 'auto',
            'httponly'    => true,
            'lifetime'    => $default_lifetime,
            'auto_detect' => true,
        ];
    }

    /**
     * Get current environment type
     *
     * @return string
     */
    public static function getEnvironment(): string
    {
        return self::detectEnvironment();
    }

    /**
     * Check if current environment is development
     *
     * @return bool
     */
    public static function isDevelopment(): bool
    {
        return self::ENV_DEVELOPMENT === self::detectEnvironment();
    }

    /**
     * Check if current environment is production
     *
     * @return bool
     */
    public static function isProduction(): bool
    {
        return self::ENV_PRODUCTION === self::detectEnvironment();
    }

    /**
     * Clear configuration cache
     */
    public static function clearCache(): void
    {
        self::$config_cache = null;
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
     * Check if debug mode is enabled
     *
     * @return bool
     */
    private static function isDebugMode(): bool
    {
        return defined('WP_DEBUG') && WP_DEBUG;
    }

    /**
     * Get saved configuration from database
     *
     * @return array<string, mixed>
     */
    private static function getSavedConfig(): array
    {
        if (function_exists('get_option')) {
            $config = get_option(self::$option_prefix, []);
            return is_array($config) ? $config : [];
        }

        return [];
    }

    /**
     * Sanitize text field
     *
     * @param mixed $value Value to sanitize
     * @return string
     */
    private static function sanitizeTextField($value): string
    {
        if (function_exists('sanitize_text_field')) {
            if (function_exists('wp_unslash')) {
                return sanitize_text_field(wp_unslash($value));
            }
            return sanitize_text_field($value);
        }

        // PHP 8.1+ deprecated FILTER_SANITIZE_STRING, use htmlspecialchars instead
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Sanitize key
     *
     * @param mixed $value Value to sanitize
     * @return string
     */
    private static function sanitizeKey($value): string
    {
        if (function_exists('sanitize_key')) {
            return sanitize_key($value);
        }

        $key = strtolower($value);
        $key = preg_replace('/[^a-z0-9_\-]/', '', $key);
        return $key;
    }
}

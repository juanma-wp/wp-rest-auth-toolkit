<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\OAuth2;

/**
 * OAuth2 Scope Handler
 *
 * Manages OAuth2 scopes: validation, parsing, and permission checking.
 * Implements RFC 6749 Section 3.3 (Access Token Scope).
 *
 * @package WPRestAuth\AuthToolkit\OAuth2
 */
class Scope
{
    /**
     * Default available scopes with descriptions
     */
    private const DEFAULT_SCOPES = [
        'read'               => 'View posts, pages, and profile information',
        'write'              => 'Create and edit posts and pages',
        'delete'             => 'Delete posts and pages',
        'manage_users'       => 'View and manage user accounts',
        'upload_files'       => 'Upload and manage media files',
        'edit_theme'         => 'Modify theme and appearance settings',
        'moderate_comments'  => 'Moderate and manage comments',
        'view_stats'         => 'Access website statistics and analytics',
        'manage_categories'  => 'Create and manage categories and tags',
        'manage_plugins'     => 'Install and manage plugins',
        'manage_options'     => 'Modify site settings and options',
    ];

    /**
     * Scope to WordPress capability mapping
     */
    private const SCOPE_CAPABILITIES = [
        'read'               => 'read',
        'write'              => 'edit_posts',
        'delete'             => 'delete_posts',
        'manage_users'       => 'list_users',
        'upload_files'       => 'upload_files',
        'edit_theme'         => 'edit_theme_options',
        'moderate_comments'  => 'moderate_comments',
        'view_stats'         => 'view_query_monitor',
        'manage_categories'  => 'manage_categories',
        'manage_plugins'     => 'activate_plugins',
        'manage_options'     => 'manage_options',
    ];

    /**
     * Validate scope format per RFC 6749
     *
     * OAuth2 scope must be alphanumeric with underscores, colons, dots, and hyphens.
     *
     * @param string $scope Scope to validate
     * @return bool True if valid
     */
    public static function validate(string $scope): bool
    {
        return preg_match('/^[a-zA-Z0-9_:.-]+$/', $scope) === 1;
    }

    /**
     * Parse space-separated scope string into array
     *
     * @param string $scope_string Space-separated scopes
     * @return array Validated scopes array
     */
    public static function parse(string $scope_string): array
    {
        $scopes = array_filter(array_map('trim', explode(' ', $scope_string)));
        return array_filter($scopes, [self::class, 'validate']);
    }

    /**
     * Convert scope array to space-separated string
     *
     * @param array $scopes Scopes array
     * @return string Space-separated scope string
     */
    public static function toString(array $scopes): string
    {
        return implode(' ', array_filter($scopes, [self::class, 'validate']));
    }

    /**
     * Check if user has access to requested scopes
     *
     * @param object $user User object (WP_User or similar)
     * @param array $scopes Requested scopes
     * @param array|null $capability_map Custom capability mapping
     * @return bool True if user has all required capabilities
     */
    public static function userHasAccess($user, array $scopes, ?array $capability_map = null): bool
    {
        $capability_map = $capability_map ?? self::SCOPE_CAPABILITIES;

        foreach ($scopes as $scope) {
            if (!isset($capability_map[$scope])) {
                return false;
            }

            $capability = $capability_map[$scope];

            // Use WordPress user_can if available
            if (function_exists('user_can')) {
                if (!user_can($user, $capability)) {
                    return false;
                }
            } elseif (method_exists($user, 'has_cap')) {
                if (!$user->has_cap($capability)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * Get available scopes with descriptions
     *
     * @param bool $apply_filters Apply WordPress filters
     * @return array Scopes with descriptions
     */
    public static function getAvailable(bool $apply_filters = true): array
    {
        $scopes = self::DEFAULT_SCOPES;

        if ($apply_filters && function_exists('apply_filters')) {
            $scopes = apply_filters('wp_auth_oauth2_available_scopes', $scopes);
        }

        return $scopes;
    }

    /**
     * Check if scope exists
     *
     * @param string $scope Scope to check
     * @return bool True if scope exists
     */
    public static function exists(string $scope): bool
    {
        return array_key_exists($scope, self::getAvailable());
    }

    /**
     * Get scope description
     *
     * @param string $scope Scope name
     * @return string|null Scope description or null if not found
     */
    public static function getDescription(string $scope): ?string
    {
        $scopes = self::getAvailable();
        return $scopes[$scope] ?? null;
    }

    /**
     * Filter scopes to only include valid/existing ones
     *
     * @param array $scopes Scopes to filter
     * @return array Valid scopes
     */
    public static function filter(array $scopes): array
    {
        return array_filter($scopes, [self::class, 'exists']);
    }

    /**
     * Check if user can grant specific scopes
     *
     * Users can only grant scopes they have capabilities for.
     *
     * @param object $user User object
     * @param array $requested_scopes Requested scopes
     * @return array Scopes user is allowed to grant
     */
    public static function filterByUserCapabilities($user, array $requested_scopes): array
    {
        $allowed = [];

        foreach ($requested_scopes as $scope) {
            if (!isset(self::SCOPE_CAPABILITIES[$scope])) {
                continue;
            }

            $capability = self::SCOPE_CAPABILITIES[$scope];

            if (function_exists('user_can') && user_can($user, $capability)) {
                $allowed[] = $scope;
            } elseif (method_exists($user, 'has_cap') && $user->has_cap($capability)) {
                $allowed[] = $scope;
            }
        }

        return $allowed;
    }

    /**
     * Compare two scope sets
     *
     * @param array $required Required scopes
     * @param array $granted Granted scopes
     * @return bool True if granted includes all required
     */
    public static function isSubset(array $required, array $granted): bool
    {
        return count(array_diff($required, $granted)) === 0;
    }

    /**
     * Merge multiple scope strings/arrays
     *
     * @param mixed ...$scope_sets Scope strings or arrays
     * @return array Unique merged scopes
     */
    public static function merge(...$scope_sets): array
    {
        $all_scopes = [];

        foreach ($scope_sets as $set) {
            if (is_string($set)) {
                $set = self::parse($set);
            }
            $all_scopes = array_merge($all_scopes, $set);
        }

        return array_unique($all_scopes);
    }
}

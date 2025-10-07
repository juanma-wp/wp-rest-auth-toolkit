<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Token;

use WPRestAuth\AuthToolkit\Security\IpResolver;
use WPRestAuth\AuthToolkit\Security\UserAgent;

/**
 * Refresh Token Manager
 *
 * Manages refresh token lifecycle: creation, validation, rotation, and revocation.
 * Supports both JWT and OAuth2 token types with optional metadata storage.
 *
 * Database table structure expected:
 * - id (int, primary key)
 * - user_id (int)
 * - token_hash (string, indexed)
 * - expires_at (int, timestamp)
 * - created_at (int, timestamp)
 * - is_revoked (bool)
 * - token_type (string: 'jwt' or 'oauth2')
 * - user_agent (string)
 * - ip_address (string)
 * - client_id (string, optional for OAuth2)
 * - scopes (string, optional for OAuth2)
 *
 * @package WPRestAuth\AuthToolkit\Token
 */
class RefreshTokenManager
{
    private string $table_name;
    private Hasher $hasher;
    private string $token_type;
    private string $cache_group;
    private int $cache_ttl;

    /**
     * @param string $table_name Database table name (with prefix)
     * @param string $secret Secret key for token hashing
     * @param string $token_type Token type identifier ('jwt' or 'oauth2')
     * @param string $cache_group WordPress cache group name
     * @param int $cache_ttl Cache TTL in seconds (default: 300)
     */
    public function __construct(
        string $table_name,
        string $secret,
        string $token_type,
        string $cache_group,
        int $cache_ttl = 300
    ) {
        $this->table_name = $table_name;
        $this->hasher = new Hasher($secret);
        $this->token_type = $token_type;
        $this->cache_group = $cache_group;
        $this->cache_ttl = $cache_ttl;
    }

    /**
     * Store refresh token with metadata
     *
     * @param int $user_id WordPress user ID
     * @param string $refresh_token Plain refresh token
     * @param int $expires_at Expiration timestamp
     * @param array $metadata Optional metadata (client_id, scopes, etc.)
     * @return bool Success status
     */
    public function store(
        int $user_id,
        string $refresh_token,
        int $expires_at,
        array $metadata = []
    ): bool {
        global $wpdb;

        $token_hash = $this->hasher->hash($refresh_token);

        $data = [
            'user_id'    => $user_id,
            'token_hash' => $token_hash,
            'expires_at' => $expires_at,
            'created_at' => time(),
            'is_revoked' => 0,
            'token_type' => $this->token_type,
            'user_agent' => UserAgent::get(),
            'ip_address' => IpResolver::get(),
        ];

        // Merge optional metadata (client_id, scopes, etc.)
        $data = array_merge($data, $metadata);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $result = $wpdb->insert($this->table_name, $data);

        return $result !== false;
    }

    /**
     * Validate refresh token
     *
     * @param string $refresh_token Plain refresh token
     * @return array|false Token data array or false on failure
     */
    public function validate(string $refresh_token)
    {
        global $wpdb;

        $token_hash = $this->hasher->hash($refresh_token);
        $cache_key = 'refresh_token_' . md5($token_hash);

        // Try cache first
        if (function_exists('wp_cache_get')) {
            $token_data = wp_cache_get($cache_key, $this->cache_group);
            if ($token_data !== false) {
                return $token_data;
            }
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $token_data = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}refresh_tokens
                 WHERE token_hash = %s
                 AND expires_at > %d
                 AND is_revoked = 0
                 AND token_type = %s",
                $token_hash,
                time(),
                $this->token_type
            ),
            ARRAY_A
        );

        if ($token_data && function_exists('wp_cache_set')) {
            wp_cache_set($cache_key, $token_data, $this->cache_group, $this->cache_ttl);
        }

        return $token_data ?: false;
    }

    /**
     * Revoke refresh token by token value
     *
     * @param string $refresh_token Plain refresh token
     * @return bool Success status
     */
    public function revoke(string $refresh_token): bool
    {
        global $wpdb;

        $token_hash = $this->hasher->hash($refresh_token);

        // Clear cache
        if (function_exists('wp_cache_delete')) {
            $cache_key = 'refresh_token_' . md5($token_hash);
            wp_cache_delete($cache_key, $this->cache_group);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->update(
            $this->table_name,
            ['is_revoked' => 1],
            [
                'token_hash' => $token_hash,
                'token_type' => $this->token_type,
            ],
            ['%d'],
            ['%s', '%s']
        );

        return $result !== false;
    }

    /**
     * Revoke refresh token by ID
     *
     * @param int $user_id WordPress user ID
     * @param int $token_id Token record ID
     * @return bool Success status
     */
    public function revokeById(int $user_id, int $token_id): bool
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $updated = $wpdb->update(
            $this->table_name,
            ['is_revoked' => 1],
            [
                'id'         => $token_id,
                'user_id'    => $user_id,
                'token_type' => $this->token_type,
            ],
            ['%d'],
            ['%d', '%d', '%s']
        );

        return $updated !== false;
    }

    /**
     * Get user's refresh tokens
     *
     * @param int $user_id WordPress user ID
     * @param int $limit Maximum number of tokens to return
     * @param bool $active_only Return only active (non-revoked) tokens
     * @return array Array of token records
     */
    public function getUserTokens(int $user_id, int $limit = 10, bool $active_only = false): array
    {
        global $wpdb;

        // Build query conditionally
        $revoked_clause = $active_only ? 'AND is_revoked = 0' : '';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $tokens = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, created_at, expires_at, ip_address, user_agent, is_revoked
                 FROM {$wpdb->prefix}refresh_tokens
                 WHERE user_id = %d AND token_type = %s $revoked_clause
                 ORDER BY created_at DESC
                 LIMIT %d",
                $user_id,
                $this->token_type,
                $limit
            ),
            ARRAY_A
        );

        return $tokens ?: [];
    }

    /**
     * Rotate token (revoke old, create new)
     *
     * @param string $old_token Old refresh token to revoke
     * @param string $new_token New refresh token to create
     * @param int $user_id WordPress user ID
     * @param int $expires_at Expiration timestamp for new token
     * @param array $metadata Optional metadata
     * @return bool Success status
     */
    public function rotate(
        string $old_token,
        string $new_token,
        int $user_id,
        int $expires_at,
        array $metadata = []
    ): bool {
        // Revoke old token
        if (!$this->revoke($old_token)) {
            return false;
        }

        // Create new token
        return $this->store($user_id, $new_token, $expires_at, $metadata);
    }

    /**
     * Update existing token metadata
     *
     * @param int $token_id Token record ID
     * @param array $updates Fields to update
     * @return bool Success status
     */
    public function update(int $token_id, array $updates): bool
    {
        global $wpdb;

        // Prevent updating sensitive fields
        unset($updates['id'], $updates['token_hash'], $updates['user_id'], $updates['created_at']);

        if (empty($updates)) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->update(
            $this->table_name,
            $updates,
            ['id' => $token_id],
            null,
            ['%d']
        );

        return $result !== false;
    }

    /**
     * Revoke all user's tokens
     *
     * @param int $user_id WordPress user ID
     * @return bool Success status
     */
    public function revokeAllUserTokens(int $user_id): bool
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->update(
            $this->table_name,
            ['is_revoked' => 1],
            [
                'user_id'    => $user_id,
                'token_type' => $this->token_type,
            ],
            ['%d'],
            ['%d', '%s']
        );

        return $result !== false;
    }

    /**
     * Clean up expired tokens
     *
     * @return int Number of tokens deleted
     */
    public function cleanExpired(): int
    {
        global $wpdb;

        $expired_time = time() - (7 * DAY_IN_SECONDS);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}refresh_tokens WHERE token_type = %s AND expires_at < %d",
                $this->token_type,
                $expired_time
            )
        );

        return (int) $deleted;
    }
}

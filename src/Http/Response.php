<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Http;

/**
 * HTTP Response Formatter
 *
 * Provides standardized response formatting for REST APIs.
 * Compatible with WordPress WP_REST_Response and WP_Error.
 *
 * @package WPRestAuth\AuthToolkit\Http
 */
class Response
{
    /**
     * Create success response
     *
     * @param array $data Response data
     * @param string|null $message Optional success message
     * @param int $status HTTP status code
     * @return mixed WP_REST_Response if WordPress, array otherwise
     */
    public static function success(array $data = [], ?string $message = null, int $status = 200)
    {
        $response_data = [
            'success' => true,
            'data'    => $data,
        ];

        if ($message !== null) {
            $response_data['message'] = $message;
        }

        // Use WordPress REST response if available
        if (class_exists('WP_REST_Response')) {
            return new \WP_REST_Response($response_data, $status);
        }

        return $response_data;
    }

    /**
     * Create error response
     *
     * @param string $code Error code
     * @param string $message Error message
     * @param int $status HTTP status code
     * @param array $data Additional error data
     * @return mixed WP_Error if WordPress, array otherwise
     */
    public static function error(string $code, string $message, int $status = 400, array $data = [])
    {
        $error_data = array_merge(['status' => $status], $data);

        // Use WordPress WP_Error if available
        if (class_exists('WP_Error')) {
            return new \WP_Error($code, $message, $error_data);
        }

        // Fallback to array format
        return [
            'success' => false,
            'error'   => [
                'code'    => $code,
                'message' => $message,
                'status'  => $status,
                'data'    => $data,
            ],
        ];
    }

    /**
     * Create OAuth2-compliant error response
     *
     * @param string $error OAuth2 error code
     * @param string|null $description Error description
     * @param string|null $uri Error documentation URI
     * @param string|null $state OAuth2 state parameter
     * @param int $status HTTP status code
     * @return array OAuth2 error response
     */
    public static function oauth2Error(
        string $error,
        ?string $description = null,
        ?string $uri = null,
        ?string $state = null,
        int $status = 400
    ): array {
        $response = ['error' => $error];

        if ($description !== null) {
            $response['error_description'] = $description;
        }

        if ($uri !== null) {
            $response['error_uri'] = $uri;
        }

        if ($state !== null) {
            $response['state'] = $state;
        }

        // Set appropriate status code if WordPress REST available
        if (class_exists('WP_REST_Response')) {
            return (new \WP_REST_Response($response, $status))->get_data();
        }

        return $response;
    }

    /**
     * Format user data for API responses
     *
     * @param object $user User object (WP_User or similar)
     * @param bool $include_sensitive Include sensitive data like capabilities
     * @return array Formatted user data
     */
    public static function formatUser($user, bool $include_sensitive = false): array
    {
        $user_data = [
            'id'           => $user->ID ?? $user->id ?? null,
            'username'     => $user->user_login ?? $user->username ?? null,
            'email'        => $user->user_email ?? $user->email ?? null,
            'display_name' => $user->display_name ?? null,
            'first_name'   => $user->first_name ?? null,
            'last_name'    => $user->last_name ?? null,
            'registered'   => $user->user_registered ?? null,
            'roles'        => $user->roles ?? [],
        ];

        // Add avatar URL if get_avatar_url exists
        if (function_exists('get_avatar_url') && isset($user->ID)) {
            $user_data['avatar_url'] = get_avatar_url($user->ID);
        }

        // Add sensitive data if requested
        if ($include_sensitive) {
            if (is_object($user) && method_exists($user, 'get_role_caps')) {
                $user_data['capabilities'] = $user->get_role_caps();
            }
        }

        // Apply WordPress filter if available
        if (function_exists('apply_filters')) {
            $user_data = apply_filters('wp_rest_auth_user_data', $user_data, $user, $include_sensitive);
        }

        return $user_data;
    }

    /**
     * Create paginated response
     *
     * @param array $items Items array
     * @param int $total Total items count
     * @param int $page Current page
     * @param int $per_page Items per page
     * @return array Paginated response data
     */
    public static function paginated(array $items, int $total, int $page = 1, int $per_page = 10): array
    {
        $total_pages = (int) ceil($total / $per_page);

        return [
            'items'       => $items,
            'pagination'  => [
                'total'       => $total,
                'count'       => count($items),
                'per_page'    => $per_page,
                'current'     => $page,
                'total_pages' => $total_pages,
                'has_prev'    => $page > 1,
                'has_next'    => $page < $total_pages,
            ],
        ];
    }

    /**
     * Create token response (JWT or OAuth2)
     *
     * @param string $access_token Access token
     * @param string|null $refresh_token Refresh token (optional)
     * @param int $expires_in Expiration time in seconds
     * @param string $token_type Token type (default: Bearer)
     * @param array $extra Extra data (scopes, user info, etc.)
     * @return array Token response
     */
    public static function token(
        string $access_token,
        ?string $refresh_token = null,
        int $expires_in = 3600,
        string $token_type = 'Bearer',
        array $extra = []
    ): array {
        $response = [
            'access_token' => $access_token,
            'token_type'   => $token_type,
            'expires_in'   => $expires_in,
        ];

        if ($refresh_token !== null) {
            $response['refresh_token'] = $refresh_token;
        }

        return array_merge($response, $extra);
    }

    /**
     * Set HTTP status code
     *
     * @param int $code HTTP status code
     * @return void
     */
    public static function setStatus(int $code): void
    {
        if (!headers_sent()) {
            http_response_code($code);
        }
    }

    /**
     * Send JSON response and exit
     *
     * @param mixed $data Response data
     * @param int $status HTTP status code
     * @return void
     */
    public static function json($data, int $status = 200): void
    {
        self::setStatus($status);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }
}

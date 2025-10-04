# WP REST Auth Toolkit

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D7.4-blue.svg)](https://php.net)

Shared authentication utilities for WordPress REST API plugins - JWT encoding/decoding, OAuth2 helpers, refresh token management, and security utilities.

## 🎯 Purpose

This package extracts common authentication logic used across multiple WordPress REST API authentication plugins:

- **[JWT Auth Pro](https://github.com/juanma-wp/jwt-auth-pro-wp-rest-api)** - JWT authentication with refresh tokens
- **[OAuth2 Auth Pro](https://github.com/juanma-wp/wp-rest-auth-oauth2)** - OAuth 2.0 authorization code flow

By sharing this code, we ensure:
- ✅ Consistent security implementations
- ✅ Single source of truth for crypto operations
- ✅ Easier testing and maintenance
- ✅ Reduced code duplication

## 📦 What's Included

### JWT Utilities
- **Encoder** - JWT encoding and decoding (HS256)
- **Base64Url** - Base64URL encoding/decoding per RFC 7515

### Token Utilities
- **Generator** - Cryptographically secure token generation
- **Hasher** - HMAC-based token hashing
- **RefreshTokenManager** - Complete refresh token CRUD operations

### Security Utilities
- **IpResolver** - Client IP detection with proxy support
- **UserAgent** - User agent extraction and sanitization

### HTTP Utilities
- **Cookie** - HTTP-only cookie management
- **CookieConfig** - Environment-aware cookie configuration with auto-detection
- **Cors** - Cross-Origin Resource Sharing handling
- **Response** - Standardized REST API response formatting

### OAuth2 Utilities
- **Scope** - Scope validation and parsing
- **Pkce** - PKCE code challenge/verifier operations (RFC 7636)
- **RedirectUri** - Redirect URI validation

## 🚀 Installation

```bash
composer require wp-rest-auth/auth-toolkit
```

## 💡 Usage

### JWT Operations

```php
use WPRestAuth\AuthToolkit\JWT\Encoder;

$encoder = new Encoder('your-secret-key');

// Encode JWT
$token = $encoder->encode([
    'sub' => 123,
    'exp' => time() + 3600
]);

// Decode JWT
$payload = $encoder->decode($token);
if ($payload) {
    echo "User ID: " . $payload['sub'];
}
```

### Refresh Token Management

```php
use WPRestAuth\AuthToolkit\Token\RefreshTokenManager;

$manager = new RefreshTokenManager(
    table_name: $wpdb->prefix . 'jwt_refresh_tokens',
    secret: 'your-secret',
    token_type: 'jwt',
    cache_group: 'auth_tokens'
);

// Store refresh token
$manager->store(
    user_id: 123,
    refresh_token: $token,
    expires_at: time() + 2592000
);

// Validate token
$token_data = $manager->validate($token);

// Revoke token
$manager->revoke($token);
```

### Security Metadata

```php
use WPRestAuth\AuthToolkit\Security\IpResolver;
use WPRestAuth\AuthToolkit\Security\UserAgent;

// Get client IP (proxy-aware)
$ip = IpResolver::get();

// Get user agent
$ua = UserAgent::get();
```

### HTTP Utilities

```php
use WPRestAuth\AuthToolkit\Http\Cookie;
use WPRestAuth\AuthToolkit\Http\CookieConfig;
use WPRestAuth\AuthToolkit\Http\Cors;
use WPRestAuth\AuthToolkit\Http\Response;

// Get environment-aware cookie configuration
$config = CookieConfig::getConfig(
    'my_cookie_config',      // Option name
    'my_cookie',             // Filter prefix
    'MY_COOKIE'              // Constant prefix
);

// Set HTTP-only cookie
Cookie::set('refresh_token', $token, [
    'expires' => time() + 2592000,
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);

// Or use CookieConfig settings
Cookie::set('refresh_token', $token, [
    'expires' => time() + $config['lifetime'],
    'httponly' => $config['httponly'],
    'secure' => $config['secure'],
    'samesite' => $config['samesite'],
    'path' => $config['path'],
    'domain' => $config['domain']
]);

// Check environment
if (CookieConfig::isDevelopment()) {
    // Development-specific logic
}

// Handle CORS
Cors::handleRequest([
    'https://app.example.com',
    'https://admin.example.com'
]);

// Create standardized responses
$success = Response::success(['user_id' => 123]);
$error = Response::error('invalid_token', 'Token expired', 401);
```

### OAuth2 Utilities

```php
use WPRestAuth\AuthToolkit\OAuth2\Scope;
use WPRestAuth\AuthToolkit\OAuth2\Pkce;
use WPRestAuth\AuthToolkit\OAuth2\RedirectUri;

// Validate scopes
$scopes = Scope::parse('read write delete');
$valid = Scope::userHasAccess($user, $scopes);

// PKCE operations
$verifier = Pkce::generateVerifier();
$challenge = Pkce::generateChallenge($verifier, 'S256');
$valid = Pkce::verify($verifier, $challenge, 'S256');

// Validate redirect URI
$valid = RedirectUri::validate('https://app.example.com/callback');
```

## 🧪 Testing

```bash
# Run all tests
composer test

# Run PHPStan
composer phpstan

# Lint code
composer lint
composer lint-fix
```

## 📝 Requirements

- PHP 7.4+
- WordPress 5.6+ (when used in WordPress context)

## 📄 License

GPL v2 or later

## 🤝 Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

## 🔗 Related Projects

- [JWT Auth Pro](https://github.com/juanma-wp/jwt-auth-pro-wp-rest-api)
- [OAuth2 Auth Pro](https://github.com/juanma-wp/wp-rest-auth-oauth2)

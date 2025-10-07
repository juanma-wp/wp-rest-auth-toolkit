=== WP REST Auth Toolkit ===
Contributors: wordpress
Tags: authentication, jwt, oauth2, rest-api, security
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Shared authentication utilities for WordPress REST API - JWT, OAuth2, and refresh token management.

== Description ==

WP REST Auth Toolkit is a comprehensive authentication library for WordPress REST API applications. It provides:

* **JWT Authentication** - Secure JSON Web Token handling with configurable algorithms
* **OAuth2 Support** - Complete OAuth2 flow implementation with PKCE
* **Refresh Token Management** - Secure token rotation and revocation
* **Cookie Management** - HTTP-only cookie handling with security best practices
* **CORS Configuration** - Cross-origin request support for SPAs
* **Security Utilities** - IP resolution, user agent parsing, and more

This is a library package designed to be used by WordPress plugins and themes that require REST API authentication.

== Installation ==

This library is intended to be required via Composer:

`composer require wp-rest-auth/auth-toolkit`

For manual installation, download and include the library in your plugin or theme.

== Frequently Asked Questions ==

= Is this a standalone plugin? =

No, this is a library package designed to be used by other WordPress plugins and themes.

= Does it work with existing authentication plugins? =

This library provides building blocks for authentication. It's designed to be integrated into your custom authentication solution.

= Is it compatible with WordPress 6.x? =

Yes, fully compatible with WordPress 5.6 and above, including the latest WordPress 6.x versions.

== Changelog ==

= 1.0.0 =
* Initial release
* JWT authentication utilities
* OAuth2 flow implementation
* Refresh token management
* Security and HTTP utilities

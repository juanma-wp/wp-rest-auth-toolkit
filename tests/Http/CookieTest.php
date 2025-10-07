<?php

namespace WPRestAuth\AuthToolkit\Tests\Http;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Http\Cookie;

/**
 * Tests for Cookie class
 *
 * Tests cookie reading functionality including fallback to HTTP_COOKIE header.
 */
class CookieTest extends TestCase
{
    /**
     * Original $_COOKIE and $_SERVER values for restoration.
     *
     * @var array<string, mixed>
     */
    private array $originalCookie = [];
    private array $originalServer = [];

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Store originals
        $this->originalCookie = $_COOKIE ?? [];
        $this->originalServer = $_SERVER ?? [];

        // Clear cookies for clean slate
        $_COOKIE = [];
        unset($_SERVER['HTTP_COOKIE']);
    }

    /**
     * Test Cookie::get() reads from $_COOKIE superglobal.
     */
    public function testGetReadsCookieFromSuperglobal(): void
    {
        $_COOKIE['test_cookie'] = 'test_value';

        $value = Cookie::get('test_cookie');

        $this->assertSame('test_value', $value);
    }

    /**
     * Test Cookie::get() returns default when cookie doesn't exist.
     */
    public function testGetReturnsDefaultWhenCookieNotFound(): void
    {
        $value = Cookie::get('nonexistent_cookie', 'default_value');

        $this->assertSame('default_value', $value);
    }

    /**
     * Test Cookie::get() reads from HTTP_COOKIE header as fallback.
     *
     * Prevents regression where $_COOKIE wasn't populated but HTTP_COOKIE header contained the cookie.
     * This happens in some WordPress REST API cross-origin requests.
     *
     * @group regression
     */
    public function testGetFallsBackToHTTPCookieHeader(): void
    {
        // Simulate cross-origin request where $_COOKIE isn't populated
        unset($_COOKIE['refresh_token']);
        $_SERVER['HTTP_COOKIE'] = 'refresh_token=abc123; other_cookie=xyz';

        $value = Cookie::get('refresh_token');

        $this->assertSame('abc123', $value);
    }

    /**
     * Test Cookie::get() prioritizes $_COOKIE over HTTP_COOKIE header.
     */
    public function testGetPrioritizesCookieSuperglobal(): void
    {
        $_COOKIE['test_cookie'] = 'from_superglobal';
        $_SERVER['HTTP_COOKIE'] = 'test_cookie=from_header';

        $value = Cookie::get('test_cookie');

        $this->assertSame('from_superglobal', $value);
    }

    /**
     * Test Cookie::get() handles multiple cookies in HTTP_COOKIE header.
     *
     * @group regression
     */
    public function testGetParsesMultipleCookiesFromHeader(): void
    {
        $_SERVER['HTTP_COOKIE'] = 'cookie1=value1; cookie2=value2; cookie3=value3';

        $value1 = Cookie::get('cookie1');
        $value2 = Cookie::get('cookie2');
        $value3 = Cookie::get('cookie3');

        $this->assertSame('value1', $value1);
        $this->assertSame('value2', $value2);
        $this->assertSame('value3', $value3);
    }

    /**
     * Test Cookie::get() handles cookies with special characters.
     */
    public function testGetHandlesSpecialCharactersInCookieValue(): void
    {
        $_SERVER['HTTP_COOKIE'] = 'token=abc%20def%3D%3D; session=xyz123';

        $value = Cookie::get('token');

        // parse_str with str_replace decodes URL-encoded values
        $this->assertNotEmpty($value);
    }

    /**
     * Test Cookie::get() returns default when HTTP_COOKIE header is empty.
     */
    public function testGetReturnsDefaultWhenHTTPCookieHeaderEmpty(): void
    {
        $_SERVER['HTTP_COOKIE'] = '';

        $value = Cookie::get('nonexistent', 'default');

        $this->assertSame('default', $value);
    }

    /**
     * Test Cookie::get() returns default when HTTP_COOKIE header is missing.
     */
    public function testGetReturnsDefaultWhenHTTPCookieHeaderMissing(): void
    {
        unset($_SERVER['HTTP_COOKIE']);

        $value = Cookie::get('nonexistent', 'default');

        $this->assertSame('default', $value);
    }

    /**
     * Test Cookie::get() handles WordPress context (sanitize_text_field).
     *
     * This test simulates WordPress being available.
     */
    public function testGetUsesWordPressSanitizationWhenAvailable(): void
    {
        // Mock WordPress sanitize_text_field function if not available
        if (!function_exists('sanitize_text_field')) {
            eval('
                function sanitize_text_field($str) { return trim(strip_tags($str)); }
                function wp_unslash($value) { return stripslashes($value); }
            ');
        }

        $_COOKIE['test'] = 'test_value';

        $value = Cookie::get('test');

        $this->assertSame('test_value', $value);
    }

    /**
     * Tear down test environment.
     */
    protected function tearDown(): void
    {
        // Restore originals
        $_COOKIE = $this->originalCookie;
        $_SERVER = $this->originalServer;

        parent::tearDown();
    }
}

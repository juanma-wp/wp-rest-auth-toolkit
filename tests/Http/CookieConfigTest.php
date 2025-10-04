<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Tests\Http;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Http\CookieConfig;

/**
 * Cookie Configuration Unit Tests
 *
 * Tests environment detection, priority system, validation rules,
 * and configuration merging logic for CookieConfig class.
 */
class CookieConfigTest extends TestCase
{
    /**
     * Store original $_SERVER values for tearDown
     *
     * @var array<string, mixed>
     */
    private array $original_server = [];

    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Store original $_SERVER values
        $this->original_server = $_SERVER;

        // Clear configuration cache before each test
        CookieConfig::clearCache();
    }

    /**
     * Test that cookie config class exists
     */
    public function testCookieConfigClassExists(): void
    {
        $this->assertTrue(class_exists('WPRestAuth\\AuthToolkit\\Http\\CookieConfig'));
    }

    /**
     * Test getConfig returns array with required keys
     */
    public function testGetConfigReturnsRequiredKeys(): void
    {
        $config = CookieConfig::getConfig();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('enabled', $config);
        $this->assertArrayHasKey('name', $config);
        $this->assertArrayHasKey('samesite', $config);
        $this->assertArrayHasKey('secure', $config);
        $this->assertArrayHasKey('path', $config);
        $this->assertArrayHasKey('domain', $config);
        $this->assertArrayHasKey('httponly', $config);
        $this->assertArrayHasKey('lifetime', $config);
        $this->assertArrayHasKey('environment', $config);
        $this->assertArrayHasKey('auto_detect', $config);
    }

    /**
     * Test base defaults
     */
    public function testBaseDefaults(): void
    {
        $config = CookieConfig::getConfig();

        $this->assertTrue($config['enabled']);
        $this->assertSame('auth_session', $config['name']);
        $this->assertTrue($config['httponly']);
        $this->assertGreaterThan(0, $config['lifetime']);
    }

    /**
     * Test environment detection: development (localhost)
     */
    public function testEnvironmentDetectionDevelopmentLocalhost(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';

        CookieConfig::clearCache();
        $this->assertSame('development', CookieConfig::getEnvironment());
    }

    /**
     * Test environment detection: development (.local domain)
     */
    public function testEnvironmentDetectionDevelopmentLocal(): void
    {
        $_SERVER['HTTP_HOST'] = 'mysite.local';

        CookieConfig::clearCache();
        $this->assertSame('development', CookieConfig::getEnvironment());
    }

    /**
     * Test environment detection: development (.test domain)
     */
    public function testEnvironmentDetectionDevelopmentTest(): void
    {
        $_SERVER['HTTP_HOST'] = 'mysite.test';

        CookieConfig::clearCache();
        $this->assertSame('development', CookieConfig::getEnvironment());
    }

    /**
     * Test environment detection: staging
     *
     * Note: In test environment with WP_DEBUG=true, may be detected as development
     */
    public function testEnvironmentDetectionStaging(): void
    {
        $_SERVER['HTTP_HOST'] = 'staging.example.com';

        CookieConfig::clearCache();
        $environment = CookieConfig::getEnvironment();

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->assertSame('development', $environment);
        } else {
            $this->assertSame('staging', $environment);
        }
    }

    /**
     * Test environment detection: production
     *
     * Note: In test environment with WP_DEBUG=true, may be detected as development
     */
    public function testEnvironmentDetectionProduction(): void
    {
        $_SERVER['HTTP_HOST'] = 'example.com';

        CookieConfig::clearCache();
        $environment = CookieConfig::getEnvironment();

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->assertSame('development', $environment);
        } else {
            $this->assertSame('production', $environment);
        }
    }

    /**
     * Test isDevelopment helper
     */
    public function testIsDevelopmentHelper(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';
        CookieConfig::clearCache();
        $this->assertTrue(CookieConfig::isDevelopment());

        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            $_SERVER['HTTP_HOST'] = 'example.com';
            CookieConfig::clearCache();
            $this->assertFalse(CookieConfig::isDevelopment());
        }
    }

    /**
     * Test isProduction helper
     */
    public function testIsProductionHelper(): void
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            $_SERVER['HTTP_HOST'] = 'example.com';
            CookieConfig::clearCache();
            $this->assertTrue(CookieConfig::isProduction());

            $_SERVER['HTTP_HOST'] = 'localhost';
            CookieConfig::clearCache();
            $this->assertFalse(CookieConfig::isProduction());
        } else {
            $_SERVER['HTTP_HOST'] = 'example.com';
            CookieConfig::clearCache();
            $this->assertFalse(CookieConfig::isProduction());
        }
    }

    /**
     * Test environment-specific defaults: development
     */
    public function testEnvironmentDefaultsDevelopment(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';
        unset($_SERVER['HTTPS']);

        CookieConfig::clearCache();
        $config = CookieConfig::getConfig();

        $this->assertSame('development', $config['environment']);
        $this->assertSame('None', $config['samesite']);
        $this->assertIsBool($config['secure']);
    }

    /**
     * Test configuration caching
     */
    public function testConfigurationCaching(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';

        $config1 = CookieConfig::getConfig();
        $_SERVER['HTTP_HOST'] = 'example.com';
        $config2 = CookieConfig::getConfig();

        $this->assertSame($config1['environment'], $config2['environment']);
        $this->assertSame('development', $config2['environment']);

        CookieConfig::clearCache();
        $config3 = CookieConfig::getConfig();

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->assertSame('development', $config3['environment']);
        } else {
            $this->assertSame('production', $config3['environment']);
        }
    }

    /**
     * Test auto-detect enabled by default
     */
    public function testAutoDetectEnabledByDefault(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';

        CookieConfig::clearCache();
        $config = CookieConfig::getConfig();

        $this->assertTrue($config['auto_detect']);
    }

    /**
     * Test get defaults for admin panel
     */
    public function testGetDefaultsForAdminPanel(): void
    {
        $defaults = CookieConfig::getDefaults();

        $this->assertIsArray($defaults);
        $this->assertTrue($defaults['enabled']);
        $this->assertSame('auth_session', $defaults['name']);
        $this->assertSame('auto', $defaults['samesite']);
        $this->assertSame('auto', $defaults['secure']);
        $this->assertSame('auto', $defaults['path']);
        $this->assertSame('auto', $defaults['domain']);
        $this->assertTrue($defaults['httponly']);
        $this->assertTrue($defaults['auto_detect']);
    }

    /**
     * Test clear cache method
     */
    public function testClearCache(): void
    {
        $config1 = CookieConfig::getConfig();
        $this->assertNotEmpty($config1);

        CookieConfig::clearCache();

        $_SERVER['HTTP_HOST'] = 'different.example.com';
        $config2 = CookieConfig::getConfig();

        $this->assertNotEmpty($config2);
    }

    /**
     * Test all configuration keys have correct types
     */
    public function testConfigurationTypes(): void
    {
        $config = CookieConfig::getConfig();

        $this->assertIsBool($config['enabled']);
        $this->assertIsString($config['name']);
        $this->assertIsString($config['samesite']);
        $this->assertIsBool($config['secure']);
        $this->assertIsString($config['path']);
        $this->assertIsString($config['domain']);
        $this->assertIsBool($config['httponly']);
        $this->assertIsInt($config['lifetime']);
        $this->assertIsString($config['environment']);
        $this->assertIsBool($config['auto_detect']);
    }

    /**
     * Test httponly is always true by default
     */
    public function testHttpOnlyAlwaysTrue(): void
    {
        $config = CookieConfig::getConfig();
        $this->assertTrue($config['httponly']);
    }

    /**
     * Test custom option name
     */
    public function testCustomOptionName(): void
    {
        $config = CookieConfig::getConfig('custom_cookie_config');

        $this->assertIsArray($config);
        $this->assertArrayHasKey('enabled', $config);
        $this->assertArrayHasKey('name', $config);
    }

    /**
     * Test custom filter prefix
     */
    public function testCustomFilterPrefix(): void
    {
        $config = CookieConfig::getConfig(
            'custom_cookie_config',
            'custom_cookie'
        );

        $this->assertIsArray($config);
        $this->assertArrayHasKey('samesite', $config);
    }

    /**
     * Test custom constant prefix
     */
    public function testCustomConstantPrefix(): void
    {
        $config = CookieConfig::getConfig(
            'custom_cookie_config',
            'custom_cookie',
            'CUSTOM_COOKIE'
        );

        $this->assertIsArray($config);
        $this->assertGreaterThan(0, $config['lifetime']);
    }

    /**
     * Test SameSite=None requires Secure=true validation
     */
    public function testSameSiteNoneRequiresSecure(): void
    {
        $_SERVER['HTTP_HOST'] = 'localhost';
        unset($_SERVER['HTTPS']);

        CookieConfig::clearCache();
        $config = CookieConfig::getConfig();

        if ($config['samesite'] === 'None') {
            $this->assertTrue($config['secure'], 'Secure must be true when SameSite=None');
        }
    }

    /**
     * Tear down test environment
     */
    protected function tearDown(): void
    {
        $_SERVER = $this->original_server;
        CookieConfig::clearCache();
        parent::tearDown();
    }
}

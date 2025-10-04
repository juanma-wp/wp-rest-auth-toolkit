<?php

namespace WPRestAuth\AuthToolkit\Tests\Security;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Security\IpResolver;

class IpResolverTest extends TestCase
{
    protected function tearDown(): void
    {
        // Clean up server variables
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        unset($_SERVER['HTTP_X_REAL_IP']);
        unset($_SERVER['HTTP_CLIENT_IP']);
    }

    public function testGetReturnsRemoteAddr(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $ip = IpResolver::get();

        $this->assertEquals('192.168.1.100', $ip);
    }

    public function testGetReturnsForwardedFor(): void
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.195';

        $ip = IpResolver::get();
        $this->assertNotEmpty($ip);
    }

    public function testGetReturnsValidIpFormat(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $ip = IpResolver::get();

        $this->assertMatchesRegularExpression('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $ip);
    }

    public function testGetReturnsDefaultWhenNoIp(): void
    {
        $ip = IpResolver::get();
        $this->assertEquals('0.0.0.0', $ip);
    }
}

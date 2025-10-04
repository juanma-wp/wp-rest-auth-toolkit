<?php

namespace WPRestAuth\AuthToolkit\Tests\Security;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Security\UserAgent;

class UserAgentTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    public function testGetReturnsUserAgent(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test Browser)';
        $ua = UserAgent::get();

        $this->assertEquals('Mozilla/5.0 (Test Browser)', $ua);
    }

    public function testGetReturnsDefaultWhenNotSet(): void
    {
        $ua = UserAgent::get();
        $this->assertEquals('Unknown', $ua);
    }

    public function testGetSanitizesUserAgent(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test Browser)';
        $ua = UserAgent::get();

        $this->assertIsString($ua);
        $this->assertNotEmpty($ua);
    }
}

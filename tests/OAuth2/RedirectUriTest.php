<?php

namespace WPRestAuth\AuthToolkit\Tests\OAuth2;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\OAuth2\RedirectUri;

class RedirectUriTest extends TestCase
{
    public function testValidateReturnsTrueForValidHttpsUri(): void
    {
        $this->assertTrue(RedirectUri::validate('https://example.com/callback'));
    }

    public function testValidateReturnsTrueForValidHttpUri(): void
    {
        $this->assertTrue(RedirectUri::validate('http://localhost/callback'));
    }

    public function testValidateReturnsFalseForInvalidUri(): void
    {
        $this->assertFalse(RedirectUri::validate('not-a-url'));
    }

    public function testValidateReturnsFalseForEmptyUri(): void
    {
        $this->assertFalse(RedirectUri::validate(''));
    }

    public function testMatchesWithWhitelist(): void
    {
        $allowed = [
            'https://app.example.com/callback',
            'https://admin.example.com/callback',
        ];

        $this->assertTrue(RedirectUri::matches('https://app.example.com/callback', $allowed));
        $this->assertFalse(RedirectUri::matches('https://evil.com/callback', $allowed));
    }
}

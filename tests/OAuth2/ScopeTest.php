<?php

namespace WPRestAuth\AuthToolkit\Tests\OAuth2;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\OAuth2\Scope;

class ScopeTest extends TestCase
{
    public function testParseReturnsArray(): void
    {
        $scopes = Scope::parse('read write delete');
        $this->assertIsArray($scopes);
        $this->assertCount(3, $scopes);
    }

    public function testParseWithEmptyStringReturnsEmptyArray(): void
    {
        $scopes = Scope::parse('');
        $this->assertIsArray($scopes);
        $this->assertEmpty($scopes);
    }

    public function testParseTrimsWhitespace(): void
    {
        $scopes = Scope::parse('  read   write  ');
        $this->assertContains('read', $scopes);
        $this->assertContains('write', $scopes);
        $this->assertCount(2, $scopes);
    }

    public function testValidateReturnsTrueForValidScope(): void
    {
        $this->assertTrue(Scope::validate('read'));
        $this->assertTrue(Scope::validate('write'));
        $this->assertTrue(Scope::validate('manage_users'));
    }

    public function testValidateReturnsFalseForInvalidScope(): void
    {
        $this->assertFalse(Scope::validate('invalid scope'));
        $this->assertFalse(Scope::validate('scope@invalid'));
    }

    public function testValidateReturnsFalseForEmptyScope(): void
    {
        $this->assertFalse(Scope::validate(''));
    }
}

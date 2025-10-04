<?php

namespace WPRestAuth\AuthToolkit\Tests\Token;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Token\Hasher;

class HasherTest extends TestCase
{
    private Hasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new Hasher('test-secret');
    }

    public function testHashReturnsString(): void
    {
        $token = 'test-token-123';
        $hash = $this->hasher->hash($token);

        $this->assertIsString($hash);
        $this->assertNotEmpty($hash);
    }

    public function testHashIsDeterministic(): void
    {
        $token = 'test-token-123';
        $hash1 = $this->hasher->hash($token);
        $hash2 = $this->hasher->hash($token);

        $this->assertEquals($hash1, $hash2);
    }

    public function testVerifyReturnsTrueForValidToken(): void
    {
        $token = 'test-token-123';
        $hash = $this->hasher->hash($token);

        $this->assertTrue($this->hasher->verify($token, $hash));
    }

    public function testVerifyReturnsFalseForInvalidToken(): void
    {
        $token = 'test-token-123';
        $hash = $this->hasher->hash($token);

        $this->assertFalse($this->hasher->verify('wrong-token', $hash));
    }

    public function testDifferentSecretsProduceDifferentHashes(): void
    {
        $token = 'test-token-123';
        $hash1 = $this->hasher->hash($token);

        $hasher2 = new Hasher('different-secret');
        $hash2 = $hasher2->hash($token);

        $this->assertNotEquals($hash1, $hash2);
    }
}

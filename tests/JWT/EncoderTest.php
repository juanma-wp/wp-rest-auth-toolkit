<?php

namespace WPRestAuth\AuthToolkit\Tests\JWT;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\JWT\Encoder;

class EncoderTest extends TestCase
{
    private Encoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new Encoder('test-secret-key');
    }

    public function testEncodeReturnsString(): void
    {
        $payload = ['sub' => 123, 'exp' => time() + 3600];
        $token = $this->encoder->encode($payload);

        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testDecodeReturnsPayload(): void
    {
        $payload = ['sub' => 123, 'exp' => time() + 3600];
        $token = $this->encoder->encode($payload);
        $decoded = $this->encoder->decode($token);

        $this->assertIsArray($decoded);
        $this->assertEquals(123, $decoded['sub']);
    }

    public function testEncodeDecodeRoundTrip(): void
    {
        $payload = [
            'sub' => 456,
            'name' => 'Test User',
            'exp' => time() + 3600,
            'custom' => ['data' => 'value'],
        ];

        $token = $this->encoder->encode($payload);
        $decoded = $this->encoder->decode($token);

        $this->assertEquals($payload['sub'], $decoded['sub']);
        $this->assertEquals($payload['name'], $decoded['name']);
        $this->assertEquals($payload['custom'], $decoded['custom']);
    }

    public function testDecodeWithInvalidSecretReturnsFalse(): void
    {
        $payload = ['sub' => 123, 'exp' => time() + 3600];
        $token = $this->encoder->encode($payload);

        $wrongEncoder = new Encoder('wrong-secret');
        $decoded = $wrongEncoder->decode($token);

        $this->assertFalse($decoded);
    }

    public function testDecodeExpiredTokenReturnsFalse(): void
    {
        $payload = ['sub' => 123, 'exp' => time() - 3600];
        $token = $this->encoder->encode($payload);
        $decoded = $this->encoder->decode($token);

        $this->assertFalse($decoded);
    }

    public function testDecodeInvalidTokenReturnsFalse(): void
    {
        $decoded = $this->encoder->decode('invalid.token.here');
        $this->assertFalse($decoded);
    }
}

<?php

namespace WPRestAuth\AuthToolkit\Tests\JWT;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\JWT\Base64Url;

class Base64UrlTest extends TestCase
{
    public function testEncode(): void
    {
        $data = 'Hello World';
        $encoded = Base64Url::encode($data);

        $this->assertIsString($encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function testDecode(): void
    {
        $data = 'Hello World';
        $encoded = Base64Url::encode($data);
        $decoded = Base64Url::decode($encoded);

        $this->assertEquals($data, $decoded);
    }

    public function testEncodeDecodeRoundTrip(): void
    {
        $testCases = [
            'Simple text',
            'Text with special chars: !@#$%^&*()',
            json_encode(['user' => 123, 'exp' => time()]),
            '',
        ];

        foreach ($testCases as $data) {
            $encoded = Base64Url::encode($data);
            $decoded = Base64Url::decode($encoded);
            $this->assertEquals($data, $decoded);
        }
    }
}

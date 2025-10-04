<?php

namespace WPRestAuth\AuthToolkit\Tests\Token;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\Token\Generator;

class GeneratorTest extends TestCase
{
    public function testGenerateReturnsString(): void
    {
        $token = Generator::generate();
        $this->assertIsString($token);
    }

    public function testGenerateReturnsCorrectLength(): void
    {
        $token = Generator::generate(32);
        // Length parameter is in characters, not bytes
        $this->assertEquals(32, strlen($token));
    }

    public function testGenerateWithCustomLength(): void
    {
        $lengths = [16, 32, 64];

        foreach ($lengths as $length) {
            $token = Generator::generate($length);
            $this->assertEquals($length, strlen($token));
        }
    }

    public function testGenerateReturnsUniqueTokens(): void
    {
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $tokens[] = Generator::generate();
        }

        $unique = array_unique($tokens);
        $this->assertCount(100, $unique);
    }

    public function testGenerateReturnsHexString(): void
    {
        $token = Generator::generate();
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
    }
}

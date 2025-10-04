<?php

namespace WPRestAuth\AuthToolkit\Tests\OAuth2;

use PHPUnit\Framework\TestCase;
use WPRestAuth\AuthToolkit\OAuth2\Pkce;

class PkceTest extends TestCase
{
    public function testGenerateVerifierReturnsString(): void
    {
        $verifier = Pkce::generateVerifier();
        $this->assertIsString($verifier);
    }

    public function testGenerateVerifierReturnsCorrectLength(): void
    {
        $verifier = Pkce::generateVerifier();
        $this->assertGreaterThanOrEqual(43, strlen($verifier));
        $this->assertLessThanOrEqual(128, strlen($verifier));
    }

    public function testGenerateChallengeS256(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier, 'S256');

        $this->assertIsString($challenge);
        $this->assertNotEmpty($challenge);
    }

    public function testGenerateChallengePlain(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier, 'plain');

        $this->assertEquals($verifier, $challenge);
    }

    public function testVerifyWithS256ReturnsTrue(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier, 'S256');

        $this->assertTrue(Pkce::verify($verifier, $challenge, 'S256'));
    }

    public function testVerifyWithPlainReturnsTrue(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier, 'plain');

        $this->assertTrue(Pkce::verify($verifier, $challenge, 'plain'));
    }

    public function testVerifyWithWrongVerifierReturnsFalse(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier, 'S256');

        $wrongVerifier = Pkce::generateVerifier();
        $this->assertFalse(Pkce::verify($wrongVerifier, $challenge, 'S256'));
    }
}

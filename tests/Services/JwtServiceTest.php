<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\Services;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtService;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Signature;
use PHPUnit\Framework\TestCase;

class JwtServiceTest extends TestCase {

  public function testParseAndVerify_validToken_shouldReturnJwt() {
    $signatureMock = $this->createMock(Signature::class);
    $signatureMock->method('getProtectedHeader')->willReturn(['test' => 'ok']);

    $jwsMock = $this->createMock(JWS::class);
    $jwsMock->method('getPayload')->willReturn('{"test": "ok"}');
    $jwsMock->method('getSignature')->willReturn($signatureMock);

    $claimCheckerManager = $this->createMock(ClaimCheckerManager::class);
    $claimCheckerManager->method('check')->willReturn([]);

    $jwsLoader = $this->createMock(JWSLoader::class);
    $jwsLoader->method('loadAndVerifyWithKeySet')->willReturnCallback(
      function (string $token, JWKSet $keyset, ?int &$signature, ?string $payload = null) use ($jwsMock) {
        $signature = 0;
        return $jwsMock;
      });

    $jwkSet = $this->createMock(JWKSet::class);

    $jwtService = new JwtService($claimCheckerManager, $jwsLoader, $jwkSet);

    $jwt = $jwtService->parseAndVerify('token');

    $this->assertInstanceOf(Jwt::class, $jwt);
    $this->assertEquals('ok', $jwt->getClaim('test'));
    $this->assertEquals('ok', $jwt->getHeader('test'));
  }

  public function testParseAndVerify_invalidToken_shouldThrowInvalidToken() {
    $claimCheckerManager = $this->createMock(ClaimCheckerManager::class);

    $jwsLoader = $this->createMock(JWSLoader::class);
    $jwsLoader->method('loadAndVerifyWithKeySet')->willThrowException(new \Exception('Invalid token'));

    $jwkSet = $this->createMock(JWKSet::class);

    $jwtService = new JwtService($claimCheckerManager, $jwsLoader, $jwkSet);

    $this->expectException(InvalidTokenException::class);
    $jwtService->parseAndVerify('token');
  }

  public function testParseAndVerify_invalidClaim_shouldThrowInvalidToken() {
    $signatureMock = $this->createMock(Signature::class);
    $signatureMock->method('getProtectedHeader')->willReturn(['test' => 'ok']);

    $jwsMock = $this->createMock(JWS::class);
    $jwsMock->method('getPayload')->willReturn('{"test": "ok"}');
    $jwsMock->method('getSignature')->willReturn($signatureMock);

    $claimCheckerManager = $this->createMock(ClaimCheckerManager::class);
    $claimCheckerManager->method('check')->willThrowException(new InvalidClaimException('Invalid', 'test', 'test'));

    $jwsLoader = $this->createMock(JWSLoader::class);
    $jwsLoader->method('loadAndVerifyWithKeySet')->willReturnCallback(
      function (string $token, JWKSet $keyset, ?int &$signature, ?string $payload = null) use ($jwsMock) {
        $signature = 0;
        return $jwsMock;
      });

    $jwkSet = $this->createMock(JWKSet::class);

    $jwtService = new JwtService($claimCheckerManager, $jwsLoader, $jwkSet);

    $this->expectException(InvalidTokenException::class);
    $jwtService->parseAndVerify('token');
  }

}

<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\Services;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use HalloVerden\JwtAuthenticatorBundle\JwtExtractor\TokenExtractorInterface;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\JwtAuthenticator;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token\JwtPostAuthenticationToken;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticatorTest extends TestCase {

  public function testAuthenticate_validRequest_shouldReturnPassport() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $tokenExtractor->method('extractToken')->willReturn('token');

    $jwt = new Jwt(['sub' => '123'],[]);
    $jwtService = $this->createMock(JwtServiceInterface::class);
    $jwtService->method('parseAndVerify')->willReturn($jwt);


    $user = new InMemoryUser('username', 'password');
    $userProvider = $this->createMock(DummyUserProvider::class);
    $userProvider->method('loadUserByIdentifier')->willReturn($user);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = $this->createMock(Request::class);

    $passport = $jwtAuthenticator->authenticate($request);

    $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
    $this->assertEquals('token', $passport->getAttribute('token'));
    $this->assertSame($jwt, $passport->getAttribute('jwt'));
    $this->assertSame($user, $passport->getUser());
  }

  public function testAuthenticate_invalidToken_shouldThrowInvalidTokenException() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $tokenExtractor->method('extractToken')->willReturn('token');

    $jwtService = $this->createMock(JwtServiceInterface::class);
    $jwtService->method('parseAndVerify')->willThrowException(new InvalidTokenException());

    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = $this->createMock(Request::class);

    $this->expectException(InvalidTokenException::class);
    $jwtAuthenticator->authenticate($request);
  }

  public function testOnAuthenticationFailure_invalidToken_shouldReturnJsonResponse() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $jwtService = $this->createMock(JwtServiceInterface::class);
    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = $this->createMock(Request::class);

    $response = $jwtAuthenticator->onAuthenticationFailure($request, new InvalidTokenException());

    $this->assertInstanceOf(JsonResponse::class, $response);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals('{"error":"INVALID_TOKEN"}', $response->getContent());
  }

  public function testCreateToken_passport_shouldReturnJwtPostAuthenticationToken() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $jwtService = $this->createMock(JwtServiceInterface::class);
    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $user = new InMemoryUser('username', 'password');

    $jwt = new Jwt([],[]);

    $passport = $this->createMock(Passport::class);
    $passport->method('getUser')->willReturn($user);
    $passport->method('getAttribute')->willReturnCallback(function ($key) use ($jwt) {
      return match ($key) {
        'token' => 'token',
        'jwt' => $jwt,
        default => null,
      };
    });

    $token = $jwtAuthenticator->createToken($passport, 'firewall');

    $this->assertInstanceOf(JwtPostAuthenticationToken::class, $token);
    $this->assertEquals('token', $token->getToken());
    $this->assertSame($jwt, $token->getJwt());
  }

}

abstract class DummyUserProvider implements UserProviderInterface {
  public function loadUserByIdentifier(string $identifier): UserInterface {
    throw new \RuntimeException();
  }
}

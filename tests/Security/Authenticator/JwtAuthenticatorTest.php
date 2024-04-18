<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\Security\Authenticator;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use HalloVerden\JwtAuthenticatorBundle\Passport\Badge\JwtBadge;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\JwtAuthenticator;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use HalloVerden\JwtAuthenticatorBundle\TokenExtractor\TokenExtractorInterface;
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

    $jwt = new Jwt(['sub' => '123'],[], 'token');
    $jwtService = $this->createMock(JwtServiceInterface::class);
    $jwtService->method('parseAndVerify')->willReturn($jwt);


    $user = new InMemoryUser('username', 'password');
    $userProvider = $this->createMock(DummyUserProvider::class);
    $userProvider->method('loadUserByIdentifier')->willReturn($user);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = new Request();
    $passport = $jwtAuthenticator->authenticate($request);

    $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
    $this->assertSame($user, $passport->getUser());

    $jwtBadge = $passport->getBadge(JwtBadge::class);
    $this->assertInstanceOf(JwtBadge::class, $jwtBadge);
    $this->assertSame($jwt, $jwtBadge->getJwt());
  }

  public function testSupports_hasToken_shouldReturnNull() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $tokenExtractor->method('extractToken')->willReturn('token');

    $jwtService = $this->createMock(JwtServiceInterface::class);
    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = new Request();

    $supports = $jwtAuthenticator->supports($request);
    $this->assertNull($supports);
  }

  public function testSupports_noToken_shouldReturnFalse() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $tokenExtractor->method('extractToken')->willReturn(null);

    $jwtService = $this->createMock(JwtServiceInterface::class);
    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $request = new Request();

    $supports = $jwtAuthenticator->supports($request);
    $this->assertFalse($supports);
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

  public function testCreateToken_passport_shouldReturnPostAuthenticationToken() {
    $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
    $jwtService = $this->createMock(JwtServiceInterface::class);
    $userProvider = $this->createMock(DummyUserProvider::class);

    $jwtAuthenticator = new JwtAuthenticator($tokenExtractor, $jwtService, $userProvider);

    $user = new InMemoryUser('username', 'password');

    $passport = $this->createMock(Passport::class);
    $passport->method('getUser')->willReturn($user);

    $token = $jwtAuthenticator->createToken($passport, 'firewall');

    $this->assertInstanceOf(InMemoryUser::class, $token->getUser());
    $this->assertSame('username', $token->getUser()->getUserIdentifier());
  }

}

abstract class DummyUserProvider implements UserProviderInterface {
  public function loadUserByIdentifier(string $identifier): UserInterface {
    throw new \RuntimeException();
  }
}

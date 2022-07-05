<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\JwtExtractor\JwtExtractorInterface;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token\JwtPostAuthenticationToken;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator implements AuthenticatorInterface {
  private const PASSPORT_ATTRIBUTE_JWT = 'jwt';
  private const PASSPORT_ATTRIBUTE_CLAIMS = 'claims';

  /**
   * JwtAuthenticator constructor.
   */
  public function __construct(
    private readonly JwtExtractorInterface $jwtTokenExtractor,
    private readonly JwtServiceInterface $jwtService,
    private readonly UserProviderInterface $userProvider,
    private readonly string $userIdentifierClaim = 'sub') {
  }

  /**
   * @inheritDoc
   */
  public function supports(Request $request): ?bool {
    return null !== $this->jwtTokenExtractor->extractJwt($request);
  }

  /**
   * @inheritDoc
   */
  public function authenticate(Request $request): Passport {
    $jwt = $this->jwtTokenExtractor->extractJwt($request);
    $claims = $this->jwtService->parseAndVerify($jwt);

    if (!isset($claims[$this->userIdentifierClaim])) {
      throw new InvalidTokenException();
    }

    $passport = new SelfValidatingPassport(new UserBadge($claims[$this->userIdentifierClaim], $this->userProvider->loadUserByIdentifier(...)));

    $passport->setAttribute(self::PASSPORT_ATTRIBUTE_JWT, $jwt);
    $passport->setAttribute(self::PASSPORT_ATTRIBUTE_CLAIMS, $claims);

    return $passport;
  }

  /**
   * @inheritDoc
   */
  public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response {
    return null;
  }

  /**
   * @inheritDoc
   */
  public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response {
    $errorMessage = \strtr($exception->getMessageKey(), $exception->getMessageData());
    $response = new JsonResponse(['error' => $errorMessage], Response::HTTP_UNAUTHORIZED, ['WWW-Authenticate' => 'Bearer']);

    // TODO event / AuthenticationFailureHandlerInterface

    return $response;
  }

  /**
   * @inheritDoc
   */
  public function createToken(Passport $passport, string $firewallName): TokenInterface {
    $token = new JwtPostAuthenticationToken(
      $passport->getUser(),
      $firewallName,
      $passport->getUser()->getRoles(),
      $passport->getAttribute(self::PASSPORT_ATTRIBUTE_CLAIMS),
      $passport->getAttribute(self::PASSPORT_ATTRIBUTE_JWT)
    );

    // TODO event

    return $token;
  }

}

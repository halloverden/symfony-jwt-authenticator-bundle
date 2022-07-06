<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator;

use HalloVerden\JwtAuthenticatorBundle\JwtExtractor\TokenExtractorInterface;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token\JwtPostAuthenticationToken;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator implements AuthenticatorInterface {
  private const PASSPORT_ATTRIBUTE_TOKEN = 'token';
  private const PASSPORT_ATTRIBUTE_JWT = 'jwt';

  /**
   * JwtAuthenticator constructor.
   */
  public function __construct(
    private readonly TokenExtractorInterface                $jwtTokenExtractor,
    private readonly JwtServiceInterface                    $jwtService,
    private readonly UserProviderInterface                  $userProvider,
    private readonly ?AuthenticationFailureHandlerInterface $failureHandler = null,
    private readonly string                                 $userIdentifierClaim = 'sub'
  ) {
  }

  /**
   * @inheritDoc
   */
  public function supports(Request $request): ?bool {
    return null !== $this->jwtTokenExtractor->extractToken($request);
  }

  /**
   * @inheritDoc
   */
  public function authenticate(Request $request): Passport {
    $token = $this->jwtTokenExtractor->extractToken($request);
    $jwt = $this->jwtService->parseAndVerify($token);

    $passport = new SelfValidatingPassport(new UserBadge($jwt->getClaim($this->userIdentifierClaim), $this->userProvider->loadUserByIdentifier(...)));

    $passport->setAttribute(self::PASSPORT_ATTRIBUTE_TOKEN, $token);
    $passport->setAttribute(self::PASSPORT_ATTRIBUTE_JWT, $jwt);

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
    if (null !== $this->failureHandler) {
      return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    $errorMessage = \strtr($exception->getMessageKey(), $exception->getMessageData());
    return new JsonResponse(['error' => $errorMessage], Response::HTTP_UNAUTHORIZED, ['WWW-Authenticate' => 'Bearer']);
  }

  /**
   * @inheritDoc
   */
  public function createToken(Passport $passport, string $firewallName): TokenInterface {
    return new JwtPostAuthenticationToken(
      $passport->getUser(),
      $firewallName,
      $passport->getUser()->getRoles(),
      $passport->getAttribute(self::PASSPORT_ATTRIBUTE_TOKEN),
      $passport->getAttribute(self::PASSPORT_ATTRIBUTE_JWT)
    );
  }

  /**
   * @inheritDoc
   */
  public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface {
    if (!$passport instanceof Passport) {
      throw new \RuntimeException(\sprintf('$passport must be instance of %s', Passport::class));
    }

    return $this->createToken($passport, $firewallName);
  }

}

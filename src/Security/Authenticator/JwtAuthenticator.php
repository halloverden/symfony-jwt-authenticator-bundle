<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use HalloVerden\JwtAuthenticatorBundle\Security\JwtAwareUserProviderInterface;
use HalloVerden\JwtAuthenticatorBundle\TokenExtractor\TokenExtractorInterface;
use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token\JwtPostAuthenticationToken;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use HalloVerden\SymfonyAuthenticatorRestrictorBundle\Interfaces\NamedAuthenticatorInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator implements AuthenticatorInterface, NamedAuthenticatorInterface {
  public const PASSPORT_ATTRIBUTE_TOKEN = 'token';
  public const PASSPORT_ATTRIBUTE_JWT = 'jwt';

  public const REQUEST_ATTRIBUTE_TOKEN = 'security_jwt_authenticator_token';
  public const REQUEST_ATTRIBUTE_JWT = 'security_jwt_authenticator_jwt';

  /**
   * JwtAuthenticator constructor.
   */
  public function __construct(
    private readonly TokenExtractorInterface                $jwtTokenExtractor,
    private readonly JwtServiceInterface                    $jwtService,
    private readonly UserProviderInterface                  $userProvider,
    private readonly ?AuthenticationFailureHandlerInterface $failureHandler = null,
    private readonly string                                 $userIdentifierClaim = 'sub',
    private readonly string                                 $name = 'jwt_authenticator'
  ) {
  }

  /**
   * @inheritDoc
   */
  public function supports(Request $request): ?bool {
    if ($request->attributes->has(self::REQUEST_ATTRIBUTE_TOKEN) && $request->attributes->has(self::REQUEST_ATTRIBUTE_JWT)) {
      return true;
    }

    $token = $this->jwtTokenExtractor->extractToken($request);
    if (null === $token) {
      return false;
    }

    try {
      $jwt = $this->jwtService->parseAndVerify($token);
    } catch (InvalidTokenException) {
      return false;
    }

    $request->attributes->set(self::REQUEST_ATTRIBUTE_TOKEN, $token);
    $request->attributes->set(self::REQUEST_ATTRIBUTE_JWT, $jwt);
    return true;
  }

  /**
   * @inheritDoc
   */
  public function authenticate(Request $request): Passport {
    $token = $this->getToken($request);
    $jwt = $this->getJwt($request);

    $passport = new SelfValidatingPassport(new UserBadge($jwt->getClaim($this->userIdentifierClaim), fn(string $identifier) => $this->loadUser($identifier, $jwt)));

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

  /**
   * @param Request $request
   *
   * @return Jwt
   */
  private function getJwt(Request $request): Jwt {
    return $request->attributes->get(self::REQUEST_ATTRIBUTE_JWT);
  }

  /**
   * @param Request $request
   *
   * @return string
   */
  private function getToken(Request $request): string {
    return $request->attributes->get(self::REQUEST_ATTRIBUTE_TOKEN);
  }

  /**
   * @param string $identifier
   * @param Jwt    $jwt
   *
   * @return UserInterface
   */
  private function loadUser(string $identifier, Jwt $jwt): UserInterface {
    if ($this->userProvider instanceof JwtAwareUserProviderInterface) {
      $this->userProvider->loadUserByJwt($identifier, $jwt);
    }

    if (\method_exists($this->userProvider, 'loadUserByIdentifier')) {
      return $this->userProvider->loadUserByIdentifier($identifier);
    }

    return $this->userProvider->loadUserByUsername($identifier);
  }

  /**
   * @inheritDoc
   */
  public function getAuthenticatorName(): string {
    return $this->name;
  }

}

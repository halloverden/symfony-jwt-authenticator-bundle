<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator;

use HalloVerden\JwtAuthenticatorBundle\Passport\Badge\JwtBadge;
use HalloVerden\JwtAuthenticatorBundle\Security\JwtPostAuthenticationToken;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtServiceInterface;
use HalloVerden\JwtAuthenticatorBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final readonly class JwtAuthenticator implements AuthenticatorInterface {

  /**
   * JwtAuthenticator constructor.
   */
  public function __construct(
    private TokenExtractorInterface                $jwtTokenExtractor,
    private JwtServiceInterface                    $jwtService,
    private UserProviderInterface                  $userProvider,
    private ?AuthenticationFailureHandlerInterface $failureHandler = null,
    private string                                 $userIdentifierClaim = 'sub',
  ) {
  }

  /**
   * @inheritDoc
   */
  public function supports(Request $request): ?bool {
    return null === $this->jwtTokenExtractor->extractToken($request) ? false : null;
  }

  /**
   * @inheritDoc
   */
  public function authenticate(Request $request): Passport {
    $token = $this->jwtTokenExtractor->extractToken($request);
    if (!$token) {
      throw new BadCredentialsException('Invalid credentials.');
    }

    $jwt = $this->jwtService->parseAndVerify($token);
    $userBadge = new UserBadge($jwt->getClaim($this->userIdentifierClaim), $this->userProvider->loadUserByIdentifier(...), $jwt->getClaims());
    return new SelfValidatingPassport($userBadge, [new JwtBadge($jwt)]);
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
      $passport->getBadge(JwtBadge::class)->getJwt()
    );
  }

}

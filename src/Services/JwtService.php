<?php

namespace HalloVerden\JwtAuthenticatorBundle\Services;

use HalloVerden\JwtAuthenticatorBundle\Event\TokenVerifiedEvent;
use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSLoader;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class JwtService implements JwtServiceInterface {

  /**
   * JwtService constructor.
   */
  public function __construct(
    private readonly ClaimCheckerManager $claimCheckerManager,
    private readonly JWSLoader $jwsLoader,
    private readonly JWKSet $jwkSet,
    private readonly array $mandatoryClaims = [],
    private readonly ?EventDispatcherInterface $eventDispatcher = null
  ) {
  }

  /**
   * @inheritDoc
   */
  public function parseAndVerify(string $token): Jwt {
    try {
      $jwt = $this->getJwt($token);
    } catch (\Exception $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    }

    try {
      $this->claimCheckerManager->check($jwt->getClaims(), $this->mandatoryClaims);
    } catch (ClaimExceptionInterface $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    }

    $this->eventDispatcher?->dispatch(new TokenVerifiedEvent($token, $jwt));

    return $jwt;
  }

  /**
   * @param string $token
   *
   * @return Jwt
   * @throws \Exception
   */
  private function getJwt(string $token): Jwt {
    $jws = $this->jwsLoader->loadAndVerifyWithKeySet($token, $this->jwkSet, $signature);
    return new Jwt(JsonConverter::decode($jws->getPayload()), $jws->getSignature($signature)->getProtectedHeader());
  }

}

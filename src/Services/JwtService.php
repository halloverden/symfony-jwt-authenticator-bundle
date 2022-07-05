<?php

namespace HalloVerden\JwtAuthenticatorBundle\Services;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JWT;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSLoader;

class JwtService implements JwtServiceInterface {

  /**
   * JwtService constructor.
   */
  public function __construct(
    private readonly ClaimCheckerManager $claimCheckerManager,
    private readonly JWSLoader $jwsLoader,
    private readonly ?JWKSet $jwkSet = null,
    private readonly array $mandatoryClaims = []
  ) {
  }

  /**
   * @inheritDoc
   */
  public function parseAndVerify(string $token): array {
    try {
      $jwt = $this->getJwt($token);
    } catch (\Exception $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    }

    try {
      $claims = JsonConverter::decode($jwt->getPayload());
    } catch (\JsonException $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    }

    try {
      $this->claimCheckerManager->check($claims, $this->mandatoryClaims);
    } catch (ClaimExceptionInterface $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    }

    return $claims;
  }

  /**
   * @param string $token
   *
   * @return JWT
   * @throws \Exception
   */
  private function getJwt(string $token): JWT {
    if (null === $this->jwkSet) {
      return $this->jwsLoader->getSerializerManager()->unserialize($token);
    }

    return $this->jwsLoader->loadAndVerifyWithKeySet($token, $this->jwkSet, $signature);
  }

}

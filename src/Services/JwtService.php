<?php

namespace HalloVerden\JwtAuthenticatorBundle\Services;

use HalloVerden\JwtAuthenticatorBundle\Exception\InvalidTokenException;
use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Signature;

final readonly class JwtService implements JwtServiceInterface {

  /**
   * JwtService constructor.
   */
  public function __construct(
    private ClaimCheckerManager $claimCheckerManager,
    private JWSLoader           $jwsLoader,
    private JWKSet              $jwkSet,
    private array $mandatoryClaims = []
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

    return $jwt;
  }

  /**
   * @param string $token
   *
   * @return Jwt
   * @throws \Exception
   */
  private function getJwt(string $token): Jwt {
    $jws = $this->jwsLoader->getSerializerManager()->unserialize($token);

    foreach ($jws->getSignatures() as $signatureIndex => $signature) {
      $jwk = $this->getJwk($signature);
      if ($this->verifySignature($jws, $signatureIndex, $jwk ? new JWKSet([$jwk]) : null)) {
        return new Jwt(JsonConverter::decode($jws->getPayload()), $signature->getProtectedHeader(), $token);
      }
    }

    throw new InvalidTokenException();
  }

  /**
   * @param Signature $signature
   *
   * @return JWK|null
   */
  private function getJwk(Signature $signature): ?JWK {
    if (!$signature->hasProtectedHeaderParameter('kid')) {
      return null;
    }

    $kid = $signature->getProtectedHeaderParameter('kid');

    if (!$this->jwkSet->has($kid)) {
      return null;
    }

    return $this->jwkSet->get($kid);
  }

  /**
   * @param JWS         $jws
   * @param int         $signatureIndex
   * @param JWKSet|null $jwkSet
   *
   * @return bool
   */
  private function verifySignature(JWS $jws, int $signatureIndex, ?JWKSet $jwkSet): bool {
    if (null === $jwkSet) {
      $jwkSet = $this->jwkSet;
    }

    try {
      return $this->jwsLoader->getJwsVerifier()->verifyWithKeySet($jws, $jwkSet, $signatureIndex);
    } catch (\Throwable) {
      return false;
    }
  }

}

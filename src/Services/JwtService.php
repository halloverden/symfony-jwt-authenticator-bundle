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
use Symfony\Component\Stopwatch\Stopwatch;

class JwtService implements JwtServiceInterface {

  /**
   * JwtService constructor.
   */
  public function __construct(
    private readonly ClaimCheckerManager $claimCheckerManager,
    private readonly JWSLoader $jwsLoader,
    private readonly JWKSet $jwkSet,
    private readonly Stopwatch $stopwatch,
    private readonly array $mandatoryClaims = []
  ) {
  }

  /**
   * @inheritDoc
   */
  public function parseAndVerify(string $token): Jwt {
    $this->stopwatch->start('parseAndVerify');
    $this->stopwatch->start('parse');
    try {
      $jwt = $this->getJwt($token);
    } catch (\Exception $e) {
      $this->stopwatch->stop('parseAndVerify');
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    } finally {
      $this->stopwatch->stop('parse');
    }

    $this->stopwatch->start('verify');
    try {
      $this->claimCheckerManager->check($jwt->getClaims(), $this->mandatoryClaims);
    } catch (ClaimExceptionInterface $e) {
      throw new InvalidTokenException($e->getMessage(), 0, $e);
    } finally {
      $this->stopwatch->stop('verify');
    }

    $this->stopwatch->stop('parseAndVerify');
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

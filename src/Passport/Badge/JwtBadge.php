<?php

namespace HalloVerden\JwtAuthenticatorBundle\Passport\Badge;

use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

final readonly class JwtBadge implements BadgeInterface {

  /**
   * JwtBadge constructor.
   */
  public function __construct(
    private Jwt $jwt
  ) {
  }

  /**
   * @return Jwt
   */
  public function getJwt(): Jwt {
    return $this->jwt;
  }

  /**
   * @inheritDoc
   */
  public function isResolved(): bool {
    return true;
  }

}

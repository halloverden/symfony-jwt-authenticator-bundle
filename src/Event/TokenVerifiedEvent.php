<?php

namespace HalloVerden\JwtAuthenticatorBundle\Event;

use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Symfony\Contracts\EventDispatcher\Event;

class TokenVerifiedEvent extends Event {

  /**
   * TokenVerifiedEvent constructor.
   */
  public function __construct(private readonly string $token, private readonly Jwt $jwt) {
  }

  /**
   * @return string
   */
  public function getToken(): string {
    return $this->token;
  }

  /**
   * @return Jwt
   */
  public function getJwt(): Jwt {
    return $this->jwt;
  }

}

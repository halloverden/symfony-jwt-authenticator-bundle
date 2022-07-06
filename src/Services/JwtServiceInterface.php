<?php

namespace HalloVerden\JwtAuthenticatorBundle\Services;

use HalloVerden\JwtAuthenticatorBundle\Jwt;

interface JwtServiceInterface {

  /**
   * @param string $token
   *
   * @return Jwt
   */
  public function parseAndVerify(string $token): Jwt;

}

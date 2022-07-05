<?php

namespace HalloVerden\JwtAuthenticatorBundle\Services;

interface JwtServiceInterface {

  /**
   * @param string $token
   *
   * @return array claims
   */
  public function parseAndVerify(string $token): array;

}

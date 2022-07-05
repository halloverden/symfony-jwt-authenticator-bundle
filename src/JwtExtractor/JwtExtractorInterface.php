<?php

namespace HalloVerden\JwtAuthenticatorBundle\JwtExtractor;

use Symfony\Component\HttpFoundation\Request;

interface JwtExtractorInterface {

  /**
   * Extracts jwt from the Request
   *
   * @param Request $request
   *
   * @return string|null
   */
  public function extractJwt(Request $request): ?string;

}

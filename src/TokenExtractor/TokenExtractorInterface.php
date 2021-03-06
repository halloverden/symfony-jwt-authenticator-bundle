<?php

namespace HalloVerden\JwtAuthenticatorBundle\TokenExtractor;

use Symfony\Component\HttpFoundation\Request;

interface TokenExtractorInterface {

  /**
   * Extracts jwt from the Request
   *
   * @param Request $request
   *
   * @return string|null
   */
  public function extractToken(Request $request): ?string;

}

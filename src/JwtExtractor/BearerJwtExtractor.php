<?php

namespace HalloVerden\JwtAuthenticatorBundle\JwtExtractor;

use Symfony\Component\HttpFoundation\Request;

class BearerJwtExtractor implements JwtExtractorInterface {
  private const HEADER_AUTHORIZATION = 'Authorization';
  private const AUTHORIZATION_TYPE_BEARER = 'Bearer';

  /**
   * @inheritDoc
   */
  public function extractJwt(Request $request): ?string {
    if (!$request->headers->has(self::HEADER_AUTHORIZATION)) {
      return null;
    }

    $typeAndToken = explode(' ', $request->headers->get(self::HEADER_AUTHORIZATION));

    if (count($typeAndToken) !== 2) {
      return null;
    }

    if ($typeAndToken[0] !== self::AUTHORIZATION_TYPE_BEARER) {
      return null;
    }

    return $typeAndToken[1];
  }

}

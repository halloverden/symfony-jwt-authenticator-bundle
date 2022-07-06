<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\TokenExtractor;

use HalloVerden\JwtAuthenticatorBundle\TokenExtractor\BearerTokenExtractor;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class BearerTokenExtractorTest extends TestCase {

  public function testExtractToken_requestWithToken_shouldReturnToken() {
    $request = new Request();
    $request->headers->set('Authorization', 'Bearer test_token');

    $bearerTokenExtractor = new BearerTokenExtractor();
    $token = $bearerTokenExtractor->extractToken($request);

    $this->assertEquals('test_token', $token);
  }

  public function testExtractToken_requestWithoutToken_shouldReturnNull() {
    $request = new Request();

    $bearerTokenExtractor = new BearerTokenExtractor();
    $token = $bearerTokenExtractor->extractToken($request);

    $this->assertNull($token);
  }

}

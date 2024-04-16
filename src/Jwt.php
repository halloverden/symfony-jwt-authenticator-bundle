<?php

namespace HalloVerden\JwtAuthenticatorBundle;

final readonly class Jwt {

  /**
   * Jwt constructor.
   */
  public function __construct(
    private array  $claims,
    private array  $headers,
    private string $rawToken
  ) {
  }

  /**
   * @return array
   */
  public function getClaims(): array {
    return $this->claims;
  }

  /**
   * @param string $key
   *
   * @return mixed
   */
  public function getClaim(string $key): mixed {
    return $this->claims[$key] ?? null;
  }

  /**
   * @return array
   */
  public function getHeaders(): array {
    return $this->headers;
  }

  /**
   * @param string $key
   *
   * @return mixed
   */
  public function getHeader(string $key): mixed {
    return $this->headers[$key] ?? null;
  }

  /**
   * @return string
   */
  public function getRawToken(): string {
    return $this->rawToken;
  }

}

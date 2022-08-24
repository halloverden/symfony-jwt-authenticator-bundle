<?php

namespace HalloVerden\JwtAuthenticatorBundle;

final class Jwt {
  private ?string $rawToken = null;

  /**
   * Jwt constructor.
   */
  public function __construct(
    private readonly array $claims,
    private readonly array $headers
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
   * @return string|null
   */
  public function getRawToken(): ?string {
    return $this->rawToken;
  }

  /**
   * @param string|null $rawToken
   *
   * @return self
   */
  public function setRawToken(?string $rawToken): self {
    $this->rawToken = $rawToken;
    return $this;
  }

}

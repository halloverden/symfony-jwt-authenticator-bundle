<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class JwtPostAuthenticationToken extends PostAuthenticationToken {
  private array $payload;
  private string $jwt;

  /**
   * JwtPostAuthenticationToken constructor.
   *
   * @param UserInterface $user
   * @param string        $firewallName
   * @param array         $roles
   * @param array         $payload
   * @param string        $jwt
   */
  public function __construct(UserInterface $user, string $firewallName, array $roles, array $payload, string $jwt) {
    parent::__construct($user, $firewallName, $roles);
    $this->payload = $payload;
    $this->jwt = $jwt;
  }

  /**
   * @return array
   */
  public function getPayload(): array {
    return $this->payload;
  }

  /**
   * @return string
   */
  public function getJwt(): string {
    return $this->jwt;
  }

}

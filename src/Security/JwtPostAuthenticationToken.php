<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security;

use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

final class JwtPostAuthenticationToken extends PostAuthenticationToken {

  /**
   * @inheritDoc
   */
  public function __construct(UserInterface $user, string $firewallName, array $roles, private readonly Jwt $jwt) {
    parent::__construct($user, $firewallName, $roles);
  }

  /**
   * @return Jwt
   */
  public function getJwt(): Jwt {
    return $this->jwt;
  }

  public function __serialize(): array {
    return [$this->jwt, parent::__serialize()];
  }

  public function __unserialize(array $data): void {
    [$this->jwt, $parentData] = $data;
    parent::__unserialize($parentData);
  }

}

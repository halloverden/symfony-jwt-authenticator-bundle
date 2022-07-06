<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\Token;

use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class JwtPostAuthenticationToken extends PostAuthenticationToken {
  private readonly string $token;
  private readonly Jwt $jwt;

  /**
   * JwtPostAuthenticationToken constructor.
   *
   * @param UserInterface $user
   * @param string        $firewallName
   * @param array         $roles
   * @param string        $token
   * @param Jwt           $jwt
   */
  public function __construct(UserInterface $user, string $firewallName, array $roles, string $token, Jwt $jwt) {
    parent::__construct($user, $firewallName, $roles);
    $this->token = $token;
    $this->jwt = $jwt;
  }

  /**
   * @return string
   */
  public function getToken(): string {
    return $this->token;
  }

  /**
   * @return Jwt
   */
  public function getJwt(): Jwt {
    return $this->jwt;
  }

}

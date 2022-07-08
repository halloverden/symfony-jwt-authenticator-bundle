<?php

namespace HalloVerden\JwtAuthenticatorBundle\Security;

use HalloVerden\JwtAuthenticatorBundle\Jwt;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface JwtAwareUserProviderInterface extends UserProviderInterface {

  /**
   * @param string $identifier
   * @param Jwt    $jwt
   *
   * @return UserInterface
   */
  public function loadUserByJwt(string $identifier, Jwt $jwt): UserInterface;

}

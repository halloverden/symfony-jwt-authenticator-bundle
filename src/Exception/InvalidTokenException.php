<?php

namespace HalloVerden\JwtAuthenticatorBundle\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class InvalidTokenException extends AuthenticationException {
  private const MESSAGE = 'INVALID_TOKEN';

  /**
   * @inheritDoc
   */
  public function getMessageKey(): string {
    return self::MESSAGE;
  }

}

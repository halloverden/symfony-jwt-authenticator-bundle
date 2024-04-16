<?php

namespace HalloVerden\JwtAuthenticatorBundle;

use HalloVerden\JwtAuthenticatorBundle\DependencyInjection\Security\Factory\JwtAuthenticatorFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class HalloVerdenJwtAuthenticatorBundle extends Bundle {

  /**
   * @inheritDoc
   */
  public function build(ContainerBuilder $container): void {
    parent::build($container);

    /** @var SecurityExtension $extension */
    $extension = $container->getExtension('security');
    $extension->addAuthenticatorFactory(new JwtAuthenticatorFactory());
  }

}

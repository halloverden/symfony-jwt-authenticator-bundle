<?php

namespace HalloVerden\JwtAuthenticatorBundle\DependencyInjection;

use Jose\Bundle\JoseFramework\Helper\ConfigurationHelper;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class HalloVerdenJwtAuthenticatorExtension extends Extension implements PrependExtensionInterface {

  /**
   * @inheritDoc
   * @throws \Exception
   */
  public function load(array $configs, ContainerBuilder $container) {
    $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
    $loader->load('services.yaml');
  }

  /**
   * @inheritDoc
   */
  public function prepend(ContainerBuilder $container) {
    ConfigurationHelper::addJWSLoader(
      $container,
      'hallo_verden_default',
      ['jws_compact'],
      ['RS256', 'HS256'],
      []
    );

    ConfigurationHelper::addClaimChecker(
      $container,
      'hallo_verden_default',
      ['exp', 'iat', 'nbf']
    );
  }

}

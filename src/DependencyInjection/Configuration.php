<?php

namespace HalloVerden\JwtAuthenticatorBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface {

  /**
   * @inheritDoc
   */
  public function getConfigTreeBuilder(): TreeBuilder {
    $treeBuilder = new TreeBuilder('hallo_verden_jwt_authenticator');

    $treeBuilder->getRootNode()
      ->children()
      ->end();

    return $treeBuilder;
  }

}

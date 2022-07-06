<?php

namespace HalloVerden\JwtAuthenticatorBundle\DependencyInjection\Security\Factory;

use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\JwtAuthenticator;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtService;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class JwtAuthenticatorFactory implements AuthenticatorFactoryInterface {

  /**
   * @inheritDoc
   */
  public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string|array {
    $authenticatorIds = [];

    foreach ($config as $key => $c) {
      $authenticatorIds[] = $this->_createAuthenticator($container, $firewallName, $c, $userProviderId, $key);
    }

    return $authenticatorIds;
  }

  /**
   * @inheritDoc
   */
  public function getKey(): string {
    return 'hallo_verden_jwt';
  }

  /**
   * @param ArrayNodeDefinition $builder
   */
  public function addConfiguration(NodeDefinition $builder): void {
    $builder
      ->useAttributeAsKey('name')
      ->addDefaultsIfNotSet()
      ->arrayPrototype()
        ->children()
          ->scalarNode('jws_loader')->isRequired()->defaultValue('hallo_verden_default')->end()
          ->scalarNode('key_set')->end()
          ->scalarNode('claim_checker')->isRequired()->defaultValue('hallo_verden_default')->end()
          ->arrayNode('mandatory_claims')->isRequired()->defaultValue([])->scalarPrototype()->end()->end()
          ->scalarNode('jtw_extractor')->isRequired()->defaultValue('hallo_verden.jwt_extractor.bearer')->end()
          ->scalarNode('user_identifier_claim')->isRequired()->defaultValue('sub')->end()
        ->end()
      ->end();

    // get the parent array node builder ("firewalls")
    $factoryRootNode = $builder->end()->end();
    $factoryRootNode
      ->validate()
        ->ifTrue(fn($v) => isset($v[$this->getKey()]) && empty($v[$this->getKey()]))
        ->then(function ($v) {
          unset($v[$this->getKey()]);
          return $v;
        })
      ->end();
  }

  public function getPriority(): int {
    return 0;
  }

  private function _createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId, string $key): string {
    $authenticatorId = 'security.authenticator.hallo_verden_jwt.'.$key.'.'.$firewallName;
    $jwtServiceId = 'hallo_verden.jwt_service'.$key.'.'.$firewallName;

    $mandatoryClaims = $config['mandatory_claims'];
    if (\in_array($config['user_identifier_claim'], $mandatoryClaims)) {
      $mandatoryClaims[] = $config['user_identifier_claim'];
    }

    $container->register($jwtServiceId, JwtService::class)
      ->addArgument(new Reference('jose.claim_checker.' . $config['claim_checker']))
      ->addArgument(new Reference('jose.jws_loader.' .$config['jws_loader']))
      ->addArgument(isset($config['key_set']) ? new Reference('jose.key_set.' . $config['key_set']) : null)
      ->addArgument($mandatoryClaims);

    $container->register($authenticatorId, JwtAuthenticator::class)
      ->addArgument(new Reference($config['jtw_extractor']))
      ->addArgument(new Reference($jwtServiceId))
      ->addArgument(new Reference($userProviderId));

    return $authenticatorId;
  }

}

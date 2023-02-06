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
   * Added to give a proper error message if someone attempts to use the authenticator without enabling authenticator manger.
   */
  public function create() {
    throw new \LogicException("'enable_authenticator_manager' needs to be true to use the jwt authenticator");
  }

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
      ->arrayPrototype()
        ->children()
          ->scalarNode('jws_loader')->defaultValue('hallo_verden_default')->end()
          ->scalarNode('key_set')->isRequired()->end()
          ->scalarNode('claim_checker')->defaultValue('hallo_verden_default')->end()
          ->arrayNode('mandatory_claims')->defaultValue([])->scalarPrototype()->end()->end()
          ->scalarNode('token_extractor')->defaultValue('hallo_verden.token_extractor.bearer')->end()
          ->scalarNode('user_identifier_claim')->defaultValue('sub')->end()
          ->scalarNode('failure_handler')->end()
          ->scalarNode('provider')->defaultNull()->end()
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
    $jwtServiceId = 'hallo_verden.jwt_service.'.$key.'.'.$firewallName;

    $userProviderId = isset($config['provider']) ? 'security.user.provider.concrete.' . \strtolower($config['provider']) : $userProviderId;

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
      ->addArgument(new Reference($config['token_extractor']))
      ->addArgument(new Reference($jwtServiceId))
      ->addArgument(new Reference($userProviderId))
      ->addArgument(isset($config['failure_handler']) ? new Reference($config['failure_handler']): null)
      ->addArgument($config['user_identifier_claim'])
      ->addArgument('jwt_authenticator.' . $key);

    return $authenticatorId;
  }

}

<?php

namespace HalloVerden\JwtAuthenticatorBundle\DependencyInjection\Security\Factory;

use HalloVerden\JwtAuthenticatorBundle\Security\Authenticator\JwtAuthenticator;
use HalloVerden\JwtAuthenticatorBundle\Services\JwtService;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class JwtAuthenticatorFactory implements AuthenticatorFactoryInterface {

  /**
   * @inheritDoc
   */
  public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string|array {
    $tokenConfig = $config['token'];
    $authenticatorId = 'security.authenticator.hallo_verden_jwt.'.$firewallName;
    $jwtServiceId = 'hallo_verden.jwt_service.'.$firewallName;

    $userProviderId = isset($config['provider']) ? 'security.user.provider.concrete.' . \strtolower($config['provider']) : $userProviderId;

    $mandatoryClaims = $tokenConfig['mandatory_claims'];
    if (\in_array($tokenConfig['user_identifier_claim'], $mandatoryClaims)) {
      $mandatoryClaims[] = $tokenConfig['user_identifier_claim'];
    }

    $container->register($jwtServiceId, JwtService::class)
      ->addArgument(new Reference('jose.claim_checker.' . $tokenConfig['claim_checker']))
      ->addArgument(new Reference('jose.jws_loader.' .$tokenConfig['jws_loader']))
      ->addArgument(isset($tokenConfig['key_set']) ? new Reference('jose.key_set.' . $tokenConfig['key_set']) : null)
      ->addArgument($mandatoryClaims);

    $container->register($authenticatorId, JwtAuthenticator::class)
      ->addArgument(new Reference($tokenConfig['token_extractor']))
      ->addArgument(new Reference($jwtServiceId))
      ->addArgument(new Reference($userProviderId))
      ->addArgument(isset($config['failure_handler']) ? new Reference($config['failure_handler']): null)
      ->addArgument($tokenConfig['user_identifier_claim']);

    return $authenticatorId;
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
      ->children()
        ->scalarNode('provider')->defaultNull()->end()
        ->scalarNode('failure_handler')->end()
        ->arrayNode('token')
          ->addDefaultsIfNotSet()
          ->children()
            ->scalarNode('jws_loader')->defaultValue('hallo_verden_default')->end()
            ->scalarNode('key_set')->isRequired()->end()
            ->scalarNode('claim_checker')->defaultValue('hallo_verden_default')->end()
            ->arrayNode('mandatory_claims')->defaultValue([])->scalarPrototype()->end()->end()
            ->scalarNode('token_extractor')->defaultValue('hallo_verden.token_extractor.bearer')->end()
            ->scalarNode('user_identifier_claim')->defaultValue('sub')->end()
          ->end()
        ->end()
      ->end();
  }

  public function getPriority(): int {
    return 0;
  }

}

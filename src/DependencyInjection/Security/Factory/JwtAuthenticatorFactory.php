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

    foreach ($config['tokens'] as $key => $c) {
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
      ->children()
        ->scalarNode('provider')->defaultNull()->end()
        ->arrayNode('tokens')
          ->useAttributeAsKey('name')
          ->arrayPrototype()
            ->children()
              ->scalarNode('jws_loader')->defaultValue('hallo_verden_default')->end()
              ->scalarNode('key_set')->defaultNull()->end()
              ->scalarNode('key')->defaultNull()->end()
              ->scalarNode('claim_checker')->defaultValue('hallo_verden_default')->end()
              ->arrayNode('mandatory_claims')->defaultValue([])->scalarPrototype()->end()->end()
              ->scalarNode('token_extractor')->defaultValue('hallo_verden.token_extractor.bearer')->end()
              ->scalarNode('user_identifier_claim')->defaultValue('sub')->end()
              ->scalarNode('failure_handler')->end()
              ->scalarNode('provider')->defaultNull()->end()
            ->end()
            ->validate()
              ->ifTrue(function ($v) {
                return null === ($v['key_set'] ?? null) && null == ($v['key'] ?? null);
              })
              ->thenInvalid('key or key_set must be set.')
            ->end()
          ->end()
        ->end()
      ->end()
      ->beforeNormalization() // For backwards compatibility we wrap everything in "tokens" if the old config syntax is used.
        ->ifTrue(function ($v): bool {
          if (!\is_array($v)) {
            return false;
          }

          foreach ($v as $value) {
            if (!(isset($value['key_set']) && \is_scalar($value['key_set'])) && !(isset($value['key']) && \is_scalar($value['key']))) {
              return false;
            }
          }

          trigger_deprecation('halloverden/symfony-jwt-authenticator-bundle', '1.2', 'Not specifying "tokens" in "security.firewalls.hallo_verden_jwt" config is deprecated');
          return true;
        })
        ->then(fn ($v) => ['tokens' => $v])
      ->end()
      ->beforeNormalization()
        ->always(function ($v) {
          if (isset($v['provider'])) {
            return $v;
          }

          $tokens = $v['tokens'] ?? [];
          if (empty($tokens) || !\is_array($tokens)) {
            return $v;
          }

          $providers = \array_filter(\array_map(fn ($c) => $c['provider'] ?? null, $tokens));

          // If a (user) provider is set on all tokens, we set the first provider as a global provider for "hallo_verden_jwt"
          //   This will never be used, but is needed to suppress errors thrown by symfony that assumes we have no provider set.
          if (count($providers) === count($tokens)) {
            $v['provider'] = $providers[\array_key_first($providers)];
          }

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

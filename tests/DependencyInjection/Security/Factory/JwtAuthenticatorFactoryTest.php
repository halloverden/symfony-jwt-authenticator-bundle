<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\DependencyInjection\Security\Factory;

use HalloVerden\JwtAuthenticatorBundle\DependencyInjection\Security\Factory\JwtAuthenticatorFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class JwtAuthenticatorFactoryTest extends TestCase {

  public function testCreateAuthenticator_shouldCreateAuthenticators() {
    $container = new ContainerBuilder();
    $config = [
      'token' => [
        'jws_loader' => 'test_loader',
        'claim_checker' => 'test_claim_checker',
        'key_set' => 'test_key_set',
        'mandatory_claims' => [],
        'token_extractor' => 'test_token_extractor',
        'user_identifier_claim' => 'sub'
      ]
    ];
    $jwtAuthenticatorFactory = new JwtAuthenticatorFactory();

    $authenticatorId = $jwtAuthenticatorFactory->createAuthenticator($container, 'main', $config, 'userProviderId');
    $this->assertSame('security.authenticator.hallo_verden_jwt.main', $authenticatorId);

    $definitions = $container->getDefinitions();
    $this->assertArrayHasKey('security.authenticator.hallo_verden_jwt.main', $definitions);
    $this->assertArrayHasKey('hallo_verden.jwt_service.main', $definitions);
  }

}

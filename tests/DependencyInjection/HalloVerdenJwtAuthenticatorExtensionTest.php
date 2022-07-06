<?php

namespace HalloVerden\JwtAuthenticatorBundle\Tests\DependencyInjection;

use HalloVerden\JwtAuthenticatorBundle\DependencyInjection\HalloVerdenJwtAuthenticatorExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class HalloVerdenJwtAuthenticatorExtensionTest extends TestCase {

  public function testLoad_shouldLoadBearerTokenExtractor() {
    $container = new ContainerBuilder();

    $extension = new HalloVerdenJwtAuthenticatorExtension();
    $extension->load([], $container);

    $this->assertArrayHasKey('hallo_verden.token_extractor.bearer', $container->getDefinitions());
  }

}

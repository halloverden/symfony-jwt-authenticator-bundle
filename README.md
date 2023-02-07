HalloVerdenJwtAuthenticatorBundle
=================================

This bundle provides a JWT authenticator for Symfony applications.
It's using [PHP JWT Framework](https://github.com/web-token/jwt-framework) for parsing and validating the JWT.

## Installation

Make sure Composer is installed globally, as explained in the
[installation chapter](https://getcomposer.org/doc/00-intro.md)
of the Composer documentation.

### Applications that use Symfony Flex

Open a command console, enter your project directory and execute:

```console
$ composer require halloverden/symfony-jwt-authenticator-bundle
```

### Applications that don't use Symfony Flex

#### Step 1: Download the Bundle

Open a command console, enter your project directory and execute the
following command to download the latest stable version of this bundle:

```console
$ composer require halloverden/symfony-jwt-authenticator-bundle
```

#### Step 2: Enable the Bundle

Then, enable the bundle by adding it to the list of registered bundles
in the `config/bundles.php` file of your project:

```php
// config/bundles.php

return [
    // ...
    HalloVerden\JwtAuthenticatorBundle\HalloVerdenJwtAuthenticatorBundle::class => ['all' => true],
];
```

## Configuration

### Security config

The authenticator is enabled and configured in the security config.

example config:
```yaml
# config/packages/security.yaml
security:

  # ...
  firewalls:
    main:
      hallo_verden_jwt:
        provider: 'user_provider'
        tokens:
          jwt_name:
            key_set: 'my_key_set'
            jws_loader: 'hallo_verden_default'
            claim_checker: 'hallo_verden_default'
            mandatory_claims: []
            user_identifier_claim: 'sub'
            token_extractor: 'hallo_verden.token_extractor.bearer'
            failure_handler: ~
            provider: 'user_provider'
          some_other_jwt:
            key_set: 'my_ket_set'
```

For each key in `hallo_verden_jwt` an authenticator is created.

#### Key set (`key_set`)

You need to provide a key set.

See [PHP JWT Framework](https://web-token.spomky-labs.com/the-symfony-bundle/key-and-key-set-management/key-set-management-jwkset#key-sets-as-services) for how to provide a key set.

#### JWS Loader (`jws_loader`)

There is a default JWS loader provided (`hallo_verden_default`), this loader is using the `jws_compact` serializer
and supports `RS256` and `HS256` signature algorithms.

See [PHP JWT Framework](https://web-token.spomky-labs.com/the-symfony-bundle/signed-tokens/jws-verification#jws-loader-service) for how to create your own loader.

#### Claim checker (`claim_cheker`)

There is a default claim checker provided (`hallo_verden_default`), this checker checks the `exp`, `iat` and `nbf` claims.

See [PHP JWT Framework](https://web-token.spomky-labs.com/the-symfony-bundle/header-and-claim-checker-management#checker-manager-services) for how to create your own checker.

#### Mandatory claims (`mandatory_claims`)

Here you specify the claims that need to be mandatory in your JWT.
The `user_identifier_claim` is automatically added as a mandatory claim.

#### User identifier claim (`user_identifier_claim`)

This claim is sent to the user provider for retrieving the user.

#### Token extractor (`token_extractor`)

The default extractor `hallo_verden.token_extractor.bearer` get the bearer token from the authorization header.
You can create your own extractor by implementing the [TokenExtractorInterface](/src/TokenExtractor/TokenExtractorInterface.php)
and set the service id to this option.

#### Failure handler (`failure_handler`)

By default, the following response is sent on failure:
```json
{
  "error": "INVALID_TOKEN"
}
```

You can modify this by creating a service implementing the [AuthenticationFailureHandlerInterface](https://github.com/symfony/symfony/blob/6.2/src/Symfony/Component/Security/Http/Authentication/AuthenticationFailureHandlerInterface.php)
and set the service id to this option.

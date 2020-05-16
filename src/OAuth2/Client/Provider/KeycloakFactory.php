<?php

namespace App\OAuth2\Client\Provider;

use App\OAuth2\Client\Provider\Config\JwksContainer;
use App\OAuth2\Client\Provider\Config\OpenIdConfiguration;
use App\OAuth2\Client\Provider\Config\OpenIdConfigurationFactory;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use InvalidArgumentException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class KeycloakFactory
{
    /**
     * @var UrlGeneratorInterface
     */
    private $router;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * KeycloakFactory constructor.
     * @param UrlGeneratorInterface $router
     * @param ClientInterface|null $httpClient
     */
    public function __construct(
        UrlGeneratorInterface $router,
        ClientInterface $httpClient = null
    )
    {
        $this->router = $router;
        $this->httpClient = null !== $httpClient ? $httpClient : new Client();
    }

    /**
     * @param string $authServerUrl
     * @param string $realm
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectRouteName
     * @param OpenIdConfiguration $config
     * @param JwksContainer $jwksContainer
     *
     * @return Keycloak
     */
    public function buildKeycloakClient(
        string $authServerUrl,
        string $realm,
        string $clientId,
        string $clientSecret,
        string $redirectRouteName,
        OpenIdConfiguration $config,
        JwksContainer $jwksContainer
    ): Keycloak
    {
        // Build Keycloak
        return new Keycloak(
            $config,
            $jwksContainer,
            [
                Keycloak::AUTH_SERVER_URL => $authServerUrl,
                Keycloak::REALM => $realm,
                'clientId' => $clientId,
                'clientSecret' => $clientSecret,
                'redirectUri' => $this->router->generate(
                    $redirectRouteName,
                    [],
                    UrlGeneratorInterface::ABSOLUTE_URL
                ),
            ],
            [
                'httpClient' => $this->httpClient,
            ]
        );
    }

    /**
     * @param string $authServerUrl
     * @param string $realm
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectUrl
     *
     * @return Keycloak
     * @throws InvalidArgumentException
     */
    public function createFromUrl(
        string $authServerUrl,
        string $realm,
        string $clientId,
        string $clientSecret,
        string $redirectUrl
    ): Keycloak
    {
        $factory = new OpenIdConfigurationFactory($this->httpClient);
        $config = $factory->buildConfigurationFromUrl($authServerUrl . '/realms/' . $realm . '/.well-known/openid-configuration');

        // Build Keycloak
        return $this->buildKeycloakClient(
            $authServerUrl,
            $realm,
            $clientId,
            $clientSecret,
            $redirectUrl,
            $config,
            $factory->buildJwksContainerFromUrl($config->get(OpenIdConfiguration::JWKS_URI))
        );
    }
}
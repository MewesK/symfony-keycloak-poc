<?php

namespace App\OAuth2\Client\Provider\Config;

use App\OAuth2\Client\Provider\Exception\OpenIdClientException;
use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use function GuzzleHttp\json_decode as guzzle_json_decode;

class OpenIdConfigurationFactory
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * OpenIdConfigurationFactory constructor.
     * @param ClientInterface|null $httpClient
     */
    public function __construct(ClientInterface $httpClient = null)
    {
        $this->httpClient = $httpClient;
    }

    /**
     * Get OpenId Configuration from URL.
     *
     * @param string $openIdConfigUrl
     *
     * @return OpenIdConfiguration
     */
    public function buildConfigurationFromUrl(string $openIdConfigUrl): OpenIdConfiguration
    {
        $this->checkHttpClientAvailable();

        try {
            $configResponse = $this->httpClient->request('GET', $openIdConfigUrl);

            return new OpenIdConfiguration(guzzle_json_decode($configResponse->getBody()->getContents(), true));
        } catch (Exception | GuzzleException $e) {
            throw new OpenIdClientException($e);
        }
    }

    /**
     * @param string $jwksUri
     * @return JwksContainer
     */
    public function buildJwksContainerFromUrl(string $jwksUri): JwksContainer
    {
        $this->checkHttpClientAvailable();

        try {
            $configResponse = $this->httpClient->request('GET', $jwksUri);

            return $this->parseJwksContainer($configResponse->getBody()->getContents());
        } catch (Exception | GuzzleException $e) {
            throw new OpenIdClientException($e);
        }
    }

    private function checkHttpClientAvailable(): void
    {
        if (null === $this->httpClient) {
            throw new OpenIdClientException('HttpClient not available. You must set a HttpClientInterface to get config from url');
        }
    }

    /**
     * @param string $jwksResponseContent
     *
     * @return JwksContainer
     */
    private function parseJwksContainer(string $jwksResponseContent): JwksContainer
    {
        $data = guzzle_json_decode($jwksResponseContent, true);
        $keys = [];

        foreach ($data['keys'] as $key) {
            $keys[$key['kid']] = $key;
        }

        return new JwksContainer($keys);
    }
}
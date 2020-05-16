<?php

namespace App\OAuth2\Client\Provider;

use App\OAuth2\Client\Provider\Config\JwksContainer;
use App\OAuth2\Client\Provider\Config\OpenIdConfiguration;
use Firebase\JWT\JWT;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use function GuzzleHttp\json_decode as guzzle_json_decode;

class Keycloak extends AbstractProvider
{
    use BearerAuthorizationTrait;

    const AUTH_SERVER_URL = 'authServerUrl';
    const REALM = 'realm';

    /**
     * @var OpenIdConfiguration
     */
    private $openidConfiguration;

    /**
     * @var JwksContainer
     */
    private $jwksContainer;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * Keycloak constructor.
     * @param OpenIdConfiguration $configuration
     * @param JwksContainer $jwksContainer
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(
        OpenIdConfiguration $configuration,
        JwksContainer $jwksContainer,
        array $options = [],
        array $collaborators = []
    ) {
        parent::__construct($options, $collaborators);

        $this->openidConfiguration = $configuration;
        $this->jwksContainer = $jwksContainer;
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl(): ?string
    {
        return $this->openidConfiguration->get(OpenIdConfiguration::AUTHORIZATION_ENDPOINT);
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->openidConfiguration->get(OpenIdConfiguration::TOKEN_ENDPOINT);
    }

    /**
     * Returns the URL for Single-Sign Out.
     *
     * @param array $options
     * @return string
     */
    public function getLogoutUrl(array $options = [])
    {
        return $this->appendQuery(
            $this->openidConfiguration->get(OpenIdConfiguration::END_SESSION_ENDPOINT),
            $this->getAuthorizationQuery(
                $this->getAuthorizationParameters($options)
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->openidConfiguration->get(OpenIdConfiguration::USERINFO_ENDPOINT);
    }

    /**
     * @throws IdentityProviderException
     *
     * {@inheritdoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        // Decode access token
        $claims = $this->decodeJwtToken($token->getToken());

        // Decode ID token if available and merge into claims
        if (array_key_exists('id_token', $token->getValues())) {
            $claims = array_merge($claims, $this->decodeJwtToken($token->getValues()['id_token']));
        }

        // Merge user info response into claims if available
        if ($response !== null) {
            $claims = array_merge($claims, $response);
        }

        $keycloakUser = new KeycloakUser($claims);

        // Check if slice-shared session is granted for this client id. if not, throw exception.
        // This will redirect to keycloak, extend session for this client & redirect back.
        // This behavior is low-impact for the user, but we log a warning as it is unwanted.
        if ($keycloakUser->get('azp') !== $this->clientId) {
            throw new IdentityProviderException('Token is granted for another client.', null, null);
        }

        // Checking if the token issuer equals the configured issuer
        if ($keycloakUser->get('iss') !== $this->openidConfiguration->get(OpenIdConfiguration::ISSUER)) {
            throw new IdentityProviderException('Issuer identifier and issuer endpoint do not match.', null, null);
        }

        return $keycloakUser;
    }

    /**
     * @throws IdentityProviderException
     *
     * {@inheritdoc}
     */
    public function getResourceOwner(AccessToken $token)
    {
        // Fetch user info if no ID token exists
        return $this->createResourceOwner(
            !array_key_exists('id_token', $token->getValues()) ? $this->fetchResourceOwnerDetails($token) : [],
            $token
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultScopes()
    {
        return ['openid'];
    }

    /**
     * Determine the active state of an OAuth 2.0 token.
     *
     * https://tools.ietf.org/html/rfc7662
     *
     * @param AccessToken $token
     * @return KeycloakIntrospection
     * @throws IdentityProviderException
     */
    public function introspectToken(AccessToken $token): KeycloakIntrospection
    {
        try {
            $response = $this->httpClient->request(
                'POST',
                $this->openidConfiguration->get(OpenIdConfiguration::TOKEN_INTROSPECTION_ENDPOINT),
                [
                    'auth' => [$this->clientId, $this->clientSecret],
                    'form_params' => [
                        'token' => $token->getToken(),
                        'token_type_hint' => 'access_token',
                    ],
                ]
            );

            return new KeycloakIntrospection(
                guzzle_json_decode($response->getBody()->getContents(), true)
            );
        } catch (GuzzleException $exception) {
            throw new IdentityProviderException($exception->getMessage(), $exception->getCode(), null);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data['error'])) {
            $error = $data['error'].': '.$data['error_description'];
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    /**
     * @param string $token
     * @return array
     */
    private function decodeJwtToken(string $token): array
    {
        return (array) JWT::decode(
            $token,
            $this->jwksContainer->getKeyFromJwtHeaderAsPem(
                guzzle_json_decode(
                    base64_decode(
                        explode('.', $token)[0],
                        true
                    ),
                    true
                )
            ),
            $this->openidConfiguration->get(OpenIdConfiguration::ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED)
        );
    }
}
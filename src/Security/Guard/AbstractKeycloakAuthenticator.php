<?php

namespace App\Security\Guard;

use App\OAuth2\Client\Provider\Keycloak as KeycloakProvider;
use App\Security\Core\User\KeycloakUserProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

abstract class AbstractKeycloakAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var KeycloakProvider
     */
    protected $keycloakProvider;

    /**
     * KeycloakApiAuthenticator constructor.
     * @param KeycloakProvider $keycloakProvider
     */
    public function __construct(KeycloakProvider $keycloakProvider) {
        $this->keycloakProvider = $keycloakProvider;
    }

    /**
     * @param AccessToken $credentials
     * @throws IdentityProviderException
     *
     * {@inheritdoc}
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (null === $credentials) {
            // Authentication fails with HTTP Status Code 401 "Unauthorized"
            return null;
        }

        if (!$credentials instanceof AccessToken) {
            throw new \InvalidArgumentException(sprintf('Invalid credentials type "%s".', get_class($userProvider)));
        }

        if (!$userProvider instanceof KeycloakUserProvider) {
            throw new \InvalidArgumentException(sprintf('Invalid user provider class "%s".', get_class($userProvider)));
        }

        return $userProvider->loadUserByAccessToken($credentials);
    }

    /**
     * In case of OAuth, no credential check is needed.
     *
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }
}
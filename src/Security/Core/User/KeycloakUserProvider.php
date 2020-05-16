<?php

namespace App\Security\Core\User;

use App\OAuth2\Client\Provider\Exception\OpenIdClientException;
use App\OAuth2\Client\Provider\Keycloak as KeycloakProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\Intl\Exception\NotImplementedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakUserProvider implements UserProviderInterface
{
    /**
     * @var KeycloakProvider
     */
    private $keycloakProvider;

    /**
     * KeycloakUserProvider constructor.
     * @param KeycloakProvider $keycloakProvider
     */
    public function __construct(KeycloakProvider $keycloakProvider) {
        $this->keycloakProvider = $keycloakProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername(string $username)
    {
        throw new NotImplementedException('Not supported!');
    }

    /**
     * @param AccessToken $accessToken
     * @return KeycloakUser
     * @throws IdentityProviderException
     */
    public function loadUserByAccessToken(AccessToken $accessToken): KeycloakUser
    {
        return new KeycloakUser(
            $this->keycloakProvider->getResourceOwner($accessToken),
            $accessToken
        );
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        return $this->doRefreshUser($user, false);
    }

    /**
     * @param UserInterface $user
     * @return UserInterface
     */
    public function forceRefreshUser(UserInterface $user)
    {
        return $this->doRefreshUser($user, true);
    }

    /**
     * @param UserInterface $user
     * @param bool $force
     * @return KeycloakUser
     */
    public function doRefreshUser(UserInterface $user, $force = true) : KeycloakUser
    {
        if (!$user instanceof KeycloakUser) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }

        try {
            // Checking if token is expired
            if ($force || $user->getAccessToken()->hasExpired()) {
                $accessToken = $this->keycloakProvider->getAccessToken(
                    'refresh_token',
                    [
                        'refresh_token' => $user->getAccessToken()->getRefreshToken(),
                    ]
                );

                // Create fresh user
                return new KeycloakUser(
                    $this->keycloakProvider->getResourceOwner($accessToken),
                    $accessToken
                );
            }

            // Checking if token is active
            elseif (!$this->keycloakProvider->introspectToken($user->getAccessToken())->isActive()) {
                throw new AuthenticationException('Keycloak Session invalid');
            }
        } catch (IdentityProviderException $identityProviderException) {
            throw new AuthenticationException($identityProviderException);
        } catch (OpenIdClientException $openIdClientException) {
            throw new AuthenticationException($openIdClientException);
        }

        // Return old user
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass(string $class)
    {
        return KeycloakUser::class === $class;
    }
}
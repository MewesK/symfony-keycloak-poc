<?php

namespace App\Security\Core\User;

use App\OAuth2\Client\Provider\KeycloakUser as BaseUser;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Delegate for BaseUser.
 */
class KeycloakUser implements UserInterface
{
    /**
     * @var BaseUser
     */
    private $baseUser;

    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * KeycloakUser constructor.
     * @param BaseUser $baseUser
     * @param AccessToken $accessToken
     */
    public function __construct(BaseUser $baseUser, AccessToken $accessToken)
    {
        $this->baseUser = $baseUser;
        $this->accessToken = $accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        // Guarantees every user at least has ROLE_USER
        // see: https://symfony.com/doc/current/security.html#roles
        $roles = ['ROLE_USER'];

        $keycloakRealmAccess = (array) $this->baseUser->get('realm_access', []);
        $keycloakRoles = isset($keycloakRealmAccess['roles']) ? $keycloakRealmAccess['roles'] : [];
        foreach ($keycloakRoles as $keycloakRole) {
            $roles[] = 'ROLE_'.strtoupper($keycloakRole);
        }

        return array_unique($roles);
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return (string) $this->baseUser->get('preferred_username');
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
        return null;
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken(): AccessToken
    {
        return $this->accessToken;
    }
}
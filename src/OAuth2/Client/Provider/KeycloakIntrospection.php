<?php

namespace App\OAuth2\Client\Provider;

class KeycloakIntrospection
{
    /**
     * @var array
     */
    private $claims;

    /**
     * KeycloakIntrospection constructor.
     * @param array $claims
     */
    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
    }

    /**
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->claims['active'];
    }
}
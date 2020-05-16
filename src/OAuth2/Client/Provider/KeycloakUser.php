<?php

namespace App\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class KeycloakUser implements ResourceOwnerInterface
{
    /**
     * @var array
     */
    protected $claims;

    /**
     * KeycloakUser constructor.
     * @param array $claims
     */
    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->claims['sub'];
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        return $this->claims;
    }

    /**
     * Get claim if available.
     *
     * @param $name
     * @param null $default
     * @return mixed|null
     */
    public function get($name, $default = null)
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }
}
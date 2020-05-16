<?php

namespace App\OAuth2\Client\Provider\Config;

class OpenIdConfiguration
{
    const ISSUER = 'issuer';
    const AUTHORIZATION_ENDPOINT = 'authorization_endpoint';
    const TOKEN_ENDPOINT = 'token_endpoint';
    const TOKEN_INTROSPECTION_ENDPOINT = 'token_introspection_endpoint';
    const USERINFO_ENDPOINT = 'userinfo_endpoint';
    const END_SESSION_ENDPOINT = 'end_session_endpoint';
    const JWKS_URI = 'jwks_uri';
    const ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = 'id_token_signing_alg_values_supported';

    /**
     * @var array
     */
    private $config;

    /**
     * OpenIdConfiguration constructor.
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * @param string $name
     * @param null   $default
     *
     * @return mixed|null
     */
    public function get(string $name, $default = null)
    {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }
}
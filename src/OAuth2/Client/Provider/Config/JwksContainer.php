<?php

namespace App\OAuth2\Client\Provider\Config;

use App\OAuth2\Client\Provider\Exception\OpenIdClientException;
use CoderCat\JWKToPEM\JWKConverter;
use Exception;

class JwksContainer
{
    /**
     * @var array
     */
    private $keys;

    /**
     * JwksContainer constructor.
     *
     * @param array $keys
     */
    public function __construct(array $keys = [])
    {
        $this->keys = $keys;
    }

    /**
     * @param array $header
     *
     * @throws OpenIdClientException
     *
     * @return string
     */
    public function getKeyFromJwtHeaderAsPem(array $header): string
    {
        try {
            $jwkConverter = new JWKConverter();

            foreach ($this->keys as $key) {
                if ('RSA' === $key['kty']) {
                    if (!isset($header['kid']) || $key['kid'] === $header['kid']) {
                        return $jwkConverter->toPEM($key);
                    }
                } else {
                    if (isset($key['alg']) && $key['alg'] === $header['alg'] && $key['kid'] === $header['kid']) {
                        return $jwkConverter->toPEM($key);
                    }
                }
            }

            if (isset($header->kid)) {
                throw new OpenIdClientException('Unable to find a key for (algorithm, kid):'.$header['alg'].', '.$header['kid'].')');
            }
            throw new OpenIdClientException('Unable to find a key for RSA');
        } catch (OpenIdClientException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new OpenIdClientException($e);
        }
    }
}
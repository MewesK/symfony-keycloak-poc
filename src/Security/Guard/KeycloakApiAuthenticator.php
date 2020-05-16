<?php

namespace App\Security\Guard;

use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class KeycloakApiAuthenticator extends AbstractKeycloakAuthenticator
{
    /**
     * Called when authentication is needed, but it's not sent.
     *
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new JsonResponse(
            ['message' => 'Authentication Required'],
            Response::HTTP_UNAUTHORIZED
        );
    }

    /**
     * Called on every request to decide if this authenticator should be used for the request. Returning `false` will
     * cause this authenticator to be skipped.
     *
     * {@inheritdoc}
     */
    public function supports(Request $request)
    {
        return $request->headers->has('Authorization') &&
            preg_match(
                '/^Bearer [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/',
                $request->headers->get('Authorization')
            ) > 0;
    }

    /**
     * Called on every request. Return whatever credentials you want to be passed to getUser() as $credentials.
     *
     * @return AccessToken
     *
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        return new AccessToken([
            'access_token' => substr($request->headers->get('Authorization'), 7)
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new JsonResponse(
            ['message' => 'Authentication Failed'],
            Response::HTTP_UNAUTHORIZED
        );
    }

    /**
     * On success, let the request continue.
     *
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        return null;
    }

    /**
     * In case of an API token, "remember me" is not supported.
     *
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return false;
    }
}
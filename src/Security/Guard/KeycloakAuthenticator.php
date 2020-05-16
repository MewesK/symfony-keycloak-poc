<?php

namespace App\Security\Guard;

use App\OAuth2\Client\Provider\Keycloak as KeycloakProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class KeycloakAuthenticator extends AbstractKeycloakAuthenticator
{
    /**
     * @var RouterInterface
     */
    private $router;

    /**
     * @var SessionInterface
     */
    private $session;

    /**
     * KeycloakAuthenticator constructor.
     * @param KeycloakProvider $keycloakProvider
     * @param RouterInterface $router
     * @param SessionInterface $session
     */
    public function __construct(
        KeycloakProvider $keycloakProvider,
        RouterInterface $router,
        SessionInterface $session
    ) {
        parent::__construct($keycloakProvider);
        $this->router = $router;
        $this->session = $session;
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $options = [];
        if ($idpHint = $request->get('kc_idp_hint')) {
            $options['kc_idp_hint'] = $idpHint;
        }
        $authUrl = $this->keycloakProvider->getAuthorizationUrl($options);
        $this->session->set('oidc_state', $this->keycloakProvider->getState());

        return new RedirectResponse($authUrl, Response::HTTP_TEMPORARY_REDIRECT);
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request)
    {
        // Check route
        if ('keycloak_connect' === $request->attributes->get('_route')) {
            $requestState = $request->get('state');
            $sessionState = $this->session->get('oidc_state');

            // Check request state with session state
            if (null !== $requestState && $sessionState === $requestState) {
                return true;
            }

            $msg = 'States of Keycloak Connect Request do not match or are empty. ';
            $msg .= sprintf(
                'State in request is %s. ',
                null !== $requestState ? '"'.$requestState.'"' : 'empty'
            );
            $msg .= sprintf(
                'State in session is %s. ',
                null !== $sessionState ? '"'.$sessionState.'"' : 'empty'
            );

            throw new BadRequestHttpException($msg);
        }

        return false;
    }

    /**
     * @return AccessToken
     * @throws IdentityProviderException
     *
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        return $this->keycloakProvider->getAccessToken(
            'authorization_code', [
                'code' => $request->get('code'),
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new Response('Authentication Failed', Response::HTTP_UNAUTHORIZED);
    }

    /**
     * On success, redirect to the target path.
     *
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        return new RedirectResponse($request->getSession()->get('_security.'.$providerKey.'.target_path'));
    }

    /**
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return true;
    }
}
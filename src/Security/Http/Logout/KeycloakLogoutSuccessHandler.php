<?php

namespace App\Security\Http\Logout;

use App\OAuth2\Client\Provider\Keycloak as KeycloakProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

class KeycloakLogoutSuccessHandler implements LogoutSuccessHandlerInterface
{
    /**
     * @var KeycloakProvider
     */
    private $keycloakProvider;

    /**
     * @var HttpUtils
     */
    private $httpUtils;

    /**
     * @var string
     */
    private $targetUrl;

    /**
     * KeycloakLogoutSuccessHandler constructor.
     * @param KeycloakProvider $keycloakProvider
     * @param HttpUtils $httpUtils
     * @param string $targetUrl
     */
    public function __construct(
        KeycloakProvider $keycloakProvider,
        HttpUtils $httpUtils,
        string $targetUrl = '/'
    ) {
        $this->keycloakProvider = $keycloakProvider;
        $this->httpUtils = $httpUtils;
        $this->targetUrl = $targetUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function onLogoutSuccess(Request $request)
    {
        // Make targetUrl compatible with DefaultLogoutSuccessHandler
        $response = $this->httpUtils->createRedirectResponse(
            $request,
            $this->targetUrl,
            RedirectResponse::HTTP_TEMPORARY_REDIRECT
        );

        // Override final targetUrl with Keycloak logout URL
        $response->setTargetUrl(
            $this->keycloakProvider->getLogoutUrl([
                'redirect_uri' => $response->getTargetUrl()
            ])
        );

        return $response;
    }
}
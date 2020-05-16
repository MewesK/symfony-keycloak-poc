<?php

namespace App\Controller;

use App\Security\Core\User\KeycloakUserProvider;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class TestController extends AbstractController
{
    /**
     * @Route("/", name="app_unsecured")
     */
    public function unsecured()
    {
        return $this->render('base.html.twig', ['message' => 'app_secured']);
    }

    /**
     * @Route("/secured", name="app_secured")
     * @Security("is_authenticated()")
     * @param TokenStorageInterface $tokenStorage
     * @return Response
     */
    public function secured(TokenStorageInterface $tokenStorage)
    {
        dump($tokenStorage->getToken());
        return $this->render('base.html.twig', ['message' => 'app_secured']);
    }

    /**
     * @Route("/force_refresh", name="app_force_refresh")
     * @Security("is_authenticated()")
     * @param TokenStorageInterface $tokenStorage
     * @param KeycloakUserProvider $keycloakUserProvider
     * @return Response
     */
    public function forceRefresh(TokenStorageInterface $tokenStorage, KeycloakUserProvider $keycloakUserProvider)
    {
        dump($tokenStorage->getToken());
        $tokenStorage->getToken()->setUser(
            $keycloakUserProvider->forceRefreshUser(
                $tokenStorage->getToken()->getUser()
            )
        );
        dump($tokenStorage->getToken());
        return $this->render('base.html.twig', ['message' => 'app_force_refresh']);
    }

    /**
     * @Route("/api/unsecured", name="app_api_unsecured")
     */
    public function apiUnsecured()
    {
        return new JsonResponse(['app_api_unsecured']);
    }

    /**
     * @Route("/api/secured", name="app_api_secured")
     * @Security("is_authenticated()")
     */
    public function apiSecured()
    {
        return new JsonResponse(['app_api_secured']);
    }
}
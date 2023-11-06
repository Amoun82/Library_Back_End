<?php

// src/EventSubscriber/JWTResponseSubscriber.php

/**
 * * renvoyer les informations lors de la demande du token
 * */

namespace App\EventSubscriber;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;

class JWTResponseSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents()
    {
        return [
            'lexik_jwt_authentication.on_authentication_success' => ['onAuthenticationSuccessResponse', 200],
        ];
    }

    public function onAuthenticationSuccessResponse(AuthenticationSuccessEvent $event)
    {
        $data = $event->getData();
        $user = $event->getUser();

        if (!$user instanceof UserInterface) {
            return;
        }


        $data['user'] = [
            'roles' => $user->getRoles(),
            'identity' => $user->getUserIdentifier(),
            'id' => $user->getId(),
        ];

        $event->setData($data);
    }
}

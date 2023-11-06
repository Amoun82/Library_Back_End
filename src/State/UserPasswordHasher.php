<?php

/**
 * * fichier ajouter pour la hash du mot de passe les Plainpasswords ont été remplacé par Password
 */
# api/src/State/UserPasswordHasher.php
namespace App\State;
use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
final class UserPasswordHasher implements ProcessorInterface
{
    public function __construct(private readonly ProcessorInterface $processor, private readonly UserPasswordHasherInterface $passwordHasher)
    {
    }
    public function process($data, Operation $operation, array $uriVariables = [], array $context = [])
    {
        if (!$data->getPassword()) {
            return $this->processor->process($data, $operation, $uriVariables, $context);
        }
        $hashedPassword = $this->passwordHasher->hashPassword(
            $data,
            $data->getPassword()
        );
        $data->setPassword($hashedPassword);
        $data->eraseCredentials();
        return $this->processor->process($data, $operation, $uriVariables, $context);
    }
}
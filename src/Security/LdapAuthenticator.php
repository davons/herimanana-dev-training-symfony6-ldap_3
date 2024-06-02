<?php

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LdapAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(
        private readonly Ldap $ldap,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly EntityManagerInterface $entityManager,
        private readonly UserProviderInterface $userProvider,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ){
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('_username');
        $password = $request->request->get('_password');

        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $email);

        try {
            // Try LDAP authentication
            $this->ldap->bind("uid={$email},dc=example,dc=com", $password);
            $query = $this->ldap->query('dc=example,dc=com', "(uid={$email})");
            $results = $query->execute();

            if (count($results) === 0) {
                throw new CustomUserMessageAuthenticationException('User not found in LDAP.');
            }

            $entry = $results[0];
            $username = $entry->getAttribute('uid')[0];
            $fullName = $entry->getAttribute('cn')[0];
            $lastName = $entry->getAttribute('sn')[0];
            $email = $entry->getAttribute('mail')[0];

            $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

            if (!$user) {
                $user = new User();
                $user->setUsername($username);
                $user->setEmail($email);
                $user->setFirstName($fullName);
                $user->setLastName($lastName);
                $user->setRoles(['ROLE_USER']);
                $user->setPassword($this->passwordHasher->hashPassword($user, $password));
                $user->setLastLoginAt(new \DateTimeImmutable('now'));

                $this->entityManager->persist($user);
            }

            $user->setLastLoginAt(new \DateTimeImmutable('now'));
            $this->entityManager->flush();

        } catch (\Exception $e) {
            // LDAP authentication failed, fall back to database authentication
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

            if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
                throw new CustomUserMessageAuthenticationException('Invalid credentials.');
            }
        }

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($password),
            [
                new CsrfTokenBadge('authenticate', $request->getPayload()->getString('_csrf_token')),
                new RememberMeBadge(),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_home'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}

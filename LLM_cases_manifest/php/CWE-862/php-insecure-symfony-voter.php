<?php

namespace App\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
// {fact rule=missing-authorization@v1.0 defects=1}

// True Positive Examples (Insecure Symfony Voter implementations)

class BadVoter1 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['VIEW', 'EDIT'])
            && $subject instanceof \App\Entity\Post;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof UserInterface) {
            return false; // ruleid: php-insecure-symfony-voter
        }

        switch ($attribute) {
            case 'VIEW':
                return $this->canView($subject, $user); // ruleid: php-insecure-symfony-voter
            case 'EDIT':
                return $this->canEdit($subject, $user); // ruleid: php-insecure-symfony-voter
        }

        return false; // ruleid: php-insecure-symfony-voter
    }

    private function canView($post, UserInterface $user): bool
    {
        return $post->isPublic() || $post->getAuthor() === $user;
    }

    private function canEdit($post, UserInterface $user): bool
    {
        return $post->getAuthor() === $user;
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter2 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['MANAGE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return 0; // ruleid: php-insecure-symfony-voter
        }

        if ($user->isAdmin()) {
            return 1; // ruleid: php-insecure-symfony-voter
        }

        return 0; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter3 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['DELETE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return false; // ruleid: php-insecure-symfony-voter
        }

        if ($user->hasRole('ROLE_ADMIN')) {
            return true; // ruleid: php-insecure-symfony-voter
        }

        return null; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter4 extends Voter
{
    private $security;

    public function __construct(Security $security)
    {
        $this->security = $security;
    }

    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['CREATE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        if ($this->security->isGranted('ROLE_SUPER_ADMIN')) {
            return 1; // ruleid: php-insecure-symfony-voter
        }

        return $this->security->isGranted('ROLE_CONTENT_CREATOR') ? 1 : 0; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter5 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface && $user->isVerified()) {
            return 1; // ruleid: php-insecure-symfony-voter
        }
        
        return 0; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter6 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['READ', 'WRITE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): string
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return 'denied'; // ruleid: php-insecure-symfony-voter
        }

        switch ($attribute) {
            case 'READ':
                return 'granted'; // ruleid: php-insecure-symfony-voter
            case 'WRITE':
                return $user->hasRole('ROLE_EDITOR') ? 'granted' : 'denied'; // ruleid: php-insecure-symfony-voter
        }

        return 'abstain'; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter7 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['APPROVE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return false; // ruleid: php-insecure-symfony-voter
        }

        $result = $user->hasRole('ROLE_APPROVER');
        return $result; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter8 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['PUBLISH']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface && $user->getDepartment() === 'Editorial') {
            return 'yes'; // ruleid: php-insecure-symfony-voter
        }
        
        return 'no'; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter9 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $request = Request::createFromGlobals();
        $apiKey = $request->headers->get('X-API-KEY');
        
        if ($apiKey === 'valid-key') {
            return 100; // ruleid: php-insecure-symfony-voter
        }
        
        return -1; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter10 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['DOWNLOAD']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): array
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return ['granted' => false]; // ruleid: php-insecure-symfony-voter
        }
        
        return ['granted' => true, 'reason' => 'User is authenticated']; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter11 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['MODERATE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface) {
            $isModerator = $user->hasRole('ROLE_MODERATOR');
            if ($isModerator) {
                return true; // ruleid: php-insecure-symfony-voter
            }
        }
        
        return false; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter12 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['EXPORT']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return -1; // ruleid: php-insecure-symfony-voter
        }
        
        $permission = $this->calculatePermission($user);
        return $permission; // ruleid: php-insecure-symfony-voter
    }
    
    private function calculatePermission(UserInterface $user): int
    {
        return $user->hasRole('ROLE_EXPORTER') ? 1 : 0;
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter13 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return 0; // ruleid: php-insecure-symfony-voter
        }
        
        switch ($attribute) {
            case 'VIEW':
                return $user->hasPermission('view') ? 1 : 0; // ruleid: php-insecure-symfony-voter
            case 'EDIT':
                return $user->hasPermission('edit') ? 1 : 0; // ruleid: php-insecure-symfony-voter
            default:
                return -1; // ruleid: php-insecure-symfony-voter
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter14 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['CONFIGURE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): string
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return 'DENY'; // ruleid: php-insecure-symfony-voter
        }
        
        return $user->hasRole('ROLE_CONFIGURATOR') ? 'ALLOW' : 'DENY'; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

class BadVoter15 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['REVIEW']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return false; // ruleid: php-insecure-symfony-voter
        }
        
        $canReview = $user->hasRole('ROLE_REVIEWER') && $subject->getStatus() === 'PENDING';
        return $canReview; // ruleid: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

// True Negative Examples (Secure Symfony Voter implementations)

class GoodVoter1 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['VIEW', 'EDIT'])
            && $subject instanceof \App\Entity\Post;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        if (!$user instanceof UserInterface) {
            return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        switch ($attribute) {
            case 'VIEW':
                return $this->canView($subject, $user) ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
            case 'EDIT':
                return $this->canEdit($subject, $user) ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        return self::ACCESS_ABSTAIN; // ok: php-insecure-symfony-voter
    }

    private function canView($post, UserInterface $user): bool
    {
        return $post->isPublic() || $post->getAuthor() === $user;
    }

    private function canEdit($post, UserInterface $user): bool
    {
        return $post->getAuthor() === $user;
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter2 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['MANAGE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        if ($user->isAdmin()) {
            return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }

        return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter3 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['DELETE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        if ($user->hasRole('ROLE_ADMIN')) {
            return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }

        return Voter::ACCESS_ABSTAIN; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter4 extends Voter
{
    private $security;

    public function __construct(Security $security)
    {
        $this->security = $security;
    }

    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['CREATE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        if ($this->security->isGranted('ROLE_SUPER_ADMIN')) {
            return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }

        return $this->security->isGranted('ROLE_CONTENT_CREATOR') ? Voter::ACCESS_GRANTED : Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter5 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface && $user->isVerified()) {
            return self::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }
        
        return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter6 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['READ', 'WRITE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        switch ($attribute) {
            case 'READ':
                return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
            case 'WRITE':
                return $user->hasRole('ROLE_EDITOR') ? Voter::ACCESS_GRANTED : Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        return Voter::ACCESS_ABSTAIN; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter7 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['APPROVE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }

        $result = $user->hasRole('ROLE_APPROVER');
        return $result ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter8 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['PUBLISH']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface && $user->getDepartment() === 'Editorial') {
            return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }
        
        return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter9 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $request = Request::createFromGlobals();
        $apiKey = $request->headers->get('X-API-KEY');
        
        if ($apiKey === 'valid-key') {
            return self::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
        }
        
        return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter10 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['DOWNLOAD']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }
        
        // We can still log or track additional information
        $this->logAccess($user, $subject);
        
        return Voter::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
    }
    
    private function logAccess(UserInterface $user, $subject): void
    {
        // Log access attempt
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter11 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['MODERATE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if ($user instanceof UserInterface) {
            $isModerator = $user->hasRole('ROLE_MODERATOR');
            if ($isModerator) {
                return self::ACCESS_GRANTED; // ok: php-insecure-symfony-voter
            }
        }
        
        return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter12 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['EXPORT']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }
        
        $permission = $this->calculatePermission($user);
        return $permission; // ok: php-insecure-symfony-voter
    }
    
    private function calculatePermission(UserInterface $user): int
    {
        return $user->hasRole('ROLE_EXPORTER') ? Voter::ACCESS_GRANTED : Voter::ACCESS_DENIED;
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter13 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return true;
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }
        
        switch ($attribute) {
            case 'VIEW':
                return $user->hasPermission('view') ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
            case 'EDIT':
                return $user->hasPermission('edit') ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
            default:
                return self::ACCESS_ABSTAIN; // ok: php-insecure-symfony-voter
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter14 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['CONFIGURE']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }
        
        return $user->hasRole('ROLE_CONFIGURATOR') ? Voter::ACCESS_GRANTED : Voter::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

class GoodVoter15 extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, ['REVIEW']);
    }

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): int
    {
        $user = $token->getUser();
        
        if (!$user instanceof UserInterface) {
            return self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
        }
        
        $canReview = $user->hasRole('ROLE_REVIEWER') && $subject->getStatus() === 'PENDING';
        return $canReview ? self::ACCESS_GRANTED : self::ACCESS_DENIED; // ok: php-insecure-symfony-voter
    }
}
// {/fact}
<?php
// File: authorization_gates_examples.php

// Simulating Laravel's Gate facade and related classes for demonstration
class Gate {
    public static function define($ability, $callback) {
        // In a real implementation, this would store the gate definition
    }
    
    public static function allows($ability, $arguments = []) {
        // In a real implementation, this would check if the gate allows the action
        return true;
    }
    
    public static function denies($ability, $arguments = []) {
        // In a real implementation, this would check if the gate denies the action
        return false;
    }
}

class User {
    public $id;
    public $role;
    
    public function __construct($id, $role) {
        $this->id = $id;
        $this->role = $role;
    }
    
    public function can($ability, $arguments = []) {
        // In a real implementation, this would check if the user can perform the action
        return Gate::allows($ability, $arguments);
    }
}

class Post {
    public $id;
    public $user_id;
    
    public function __construct($id, $user_id) {
        $this->id = $id;
        $this->user_id = $user_id;
    }
}
// {fact rule=missing-authorization@v1.0 defects=1}

// True Positive Examples (Insecure Gate Definitions)

function bad_case_1() {
    // Gate definition that doesn't return a boolean value
    // ruleid: php-insecure-gate-definition
    Gate::define('edit-post', function ($user, $post) {
        if ($user->id == $post->user_id) {
            // No explicit return value, implicitly returns null
        }
    });
    
    $user = new User(1, 'editor');
    $post = new Post(1, 2);
    
    if ($user->can('edit-post', $post)) {
        echo "User can edit this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_2() {
    // Gate definition that returns non-boolean values
    // ruleid: php-insecure-gate-definition
    Gate::define('publish-post', function ($user, $post) {
        if ($user->role == 'editor') {
            return "allowed"; // String instead of boolean
        }
        return "denied"; // String instead of boolean
    });
    
    $user = new User(1, 'editor');
    $post = new Post(1, 2);
    
    if ($user->can('publish-post', $post)) {
        echo "User can publish this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_3() {
    // Gate definition that returns null in some cases
    // ruleid: php-insecure-gate-definition
    Gate::define('delete-post', function ($user, $post) {
        if ($user->role == 'admin') {
            return true;
        }
        // No return for non-admin users, implicitly returns null
    });
    
    $user = new User(1, 'editor');
    $post = new Post(1, 2);
    
    if ($user->can('delete-post', $post)) {
        echo "User can delete this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_4() {
    // Gate definition that returns integer values
    // ruleid: php-insecure-gate-definition
    Gate::define('view-dashboard', function ($user) {
        return $user->id; // Returns user ID instead of boolean
    });
    
    $user = new User(1, 'user');
    
    if ($user->can('view-dashboard')) {
        echo "User can view dashboard";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_5() {
    // Gate definition that returns array
    // ruleid: php-insecure-gate-definition
    Gate::define('manage-users', function ($user) {
        return ['allowed' => ($user->role == 'admin')]; // Returns array instead of boolean
    });
    
    $user = new User(1, 'admin');
    
    if ($user->can('manage-users')) {
        echo "User can manage other users";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_6() {
    // Gate definition with inconsistent return types
    // ruleid: php-insecure-gate-definition
    Gate::define('edit-settings', function ($user) {
        if ($user->role == 'admin') {
            return true;
        } elseif ($user->role == 'manager') {
            return 1; // Integer instead of boolean
        } else {
            return "no"; // String instead of boolean
        }
    });
    
    $user = new User(1, 'manager');
    
    if ($user->can('edit-settings')) {
        echo "User can edit settings";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_7() {
    // Gate definition that returns object
    // ruleid: php-insecure-gate-definition
    Gate::define('access-api', function ($user) {
        $response = new stdClass();
        $response->allowed = ($user->role == 'api-user');
        return $response; // Returns object instead of boolean
    });
    
    $user = new User(1, 'api-user');
    
    if ($user->can('access-api')) {
        echo "User can access API";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_8() {
    // Gate definition with early return but missing final return
    // ruleid: php-insecure-gate-definition
    Gate::define('download-file', function ($user, $file) {
        if ($user->role == 'premium') {
            return true;
        }
        
        if ($file->is_free) {
            return true;
        }
        // Missing return for non-premium users and non-free files
    });
    
    $user = new User(1, 'basic');
    $file = (object)['is_free' => false];
    
    if ($user->can('download-file', $file)) {
        echo "User can download this file";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_9() {
    // Gate definition that returns empty string
    // ruleid: php-insecure-gate-definition
    Gate::define('create-post', function ($user) {
        if ($user->role == 'editor' || $user->role == 'admin') {
            return true;
        }
        return ''; // Empty string instead of boolean
    });
    
    $user = new User(1, 'user');
    
    if ($user->can('create-post')) {
        echo "User can create posts";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_10() {
    // Gate definition with conditional that might not execute
    // ruleid: php-insecure-gate-definition
    Gate::define('moderate-comments', function ($user, $comment) {
        if ($user->role == 'moderator') {
            return true;
        } elseif ($comment->user_id == $user->id) {
            return true;
        }
        // No default return value
    });
    
    $user = new User(1, 'user');
    $comment = (object)['user_id' => 2];
    
    if ($user->can('moderate-comments', $comment)) {
        echo "User can moderate this comment";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_11() {
    // Gate definition returning a function
    // ruleid: php-insecure-gate-definition
    Gate::define('export-data', function ($user) {
        return function() use ($user) {
            return $user->role == 'admin';
        };
    });
    
    $user = new User(1, 'admin');
    
    if ($user->can('export-data')) {
        echo "User can export data";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_12() {
    // Gate definition with complex logic but inconsistent returns
    // ruleid: php-insecure-gate-definition
    Gate::define('manage-project', function ($user, $project) {
        if ($user->role == 'admin') {
            return 'full-access';
        } elseif ($user->id == $project->owner_id) {
            return 'owner-access';
        } elseif (in_array($user->id, $project->member_ids)) {
            return 'member-access';
        }
        return false;
    });
    
    $user = new User(1, 'user');
    $project = (object)['owner_id' => 2, 'member_ids' => [1, 3, 5]];
    
    if ($user->can('manage-project', $project)) {
        echo "User can manage this project";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_13() {
    // Gate definition with switch statement missing default
    // ruleid: php-insecure-gate-definition
    Gate::define('access-module', function ($user, $module) {
        switch ($user->role) {
            case 'admin':
                return true;
            case 'manager':
                return $module->isManagerAccessible();
            case 'user':
                return $module->isPublic();
            // No default case
        }
    });
    
    $user = new User(1, 'guest');
    $module = (object)['isManagerAccessible' => function() { return true; }, 'isPublic' => function() { return false; }];
    
    if ($user->can('access-module', $module)) {
        echo "User can access this module";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_14() {
    // Gate definition with try/catch but missing return in catch
    // ruleid: php-insecure-gate-definition
    Gate::define('process-payment', function ($user, $payment) {
        try {
            if ($user->role == 'finance' || $user->id == $payment->user_id) {
                return true;
            }
            return false;
        } catch (Exception $e) {
            // Log error but no return value
            error_log($e->getMessage());
        }
    });
    
    $user = new User(1, 'finance');
    $payment = (object)['user_id' => 2];
    
    if ($user->can('process-payment', $payment)) {
        echo "User can process this payment";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

function bad_case_15() {
    // Gate definition with ternary operator returning mixed types
    // ruleid: php-insecure-gate-definition
    Gate::define('view-reports', function ($user, $report) {
        return $user->role == 'analyst' ? true : $report->public_id;
    });
    
    $user = new User(1, 'user');
    $report = (object)['public_id' => 'REP-123'];
    
    if ($user->can('view-reports', $report)) {
        echo "User can view this report";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

// True Negative Examples (Secure Gate Definitions)

function good_case_1() {
    // Gate definition that properly returns boolean values
    // ok: php-insecure-gate-definition
    Gate::define('edit-post', function ($user, $post) {
        return $user->id == $post->user_id;
    });
    
    $user = new User(1, 'editor');
    $post = new Post(1, 1);
    
    if ($user->can('edit-post', $post)) {
        echo "User can edit this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_2() {
    // Gate definition with multiple conditions but always returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('publish-post', function ($user, $post) {
        if ($user->role == 'admin') {
            return true;
        }
        
        if ($user->role == 'editor') {
            return true;
        }
        
        return false;
    });
    
    $user = new User(1, 'editor');
    $post = new Post(1, 2);
    
    if ($user->can('publish-post', $post)) {
        echo "User can publish this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_3() {
    // Gate definition with complex logic but always returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('delete-post', function ($user, $post) {
        // Admin can delete any post
        if ($user->role == 'admin') {
            return true;
        }
        
        // Users can delete their own posts
        if ($user->id == $post->user_id) {
            return true;
        }
        
        // All other cases are denied
        return false;
    });
    
    $user = new User(1, 'user');
    $post = new Post(1, 1);
    
    if ($user->can('delete-post', $post)) {
        echo "User can delete this post";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_4() {
    // Gate definition using ternary operator with boolean result
    // ok: php-insecure-gate-definition
    Gate::define('view-dashboard', function ($user) {
        return $user->role == 'admin' ? true : false;
    });
    
    $user = new User(1, 'admin');
    
    if ($user->can('view-dashboard')) {
        echo "User can view dashboard";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_5() {
    // Gate definition with direct boolean expression
    // ok: php-insecure-gate-definition
    Gate::define('manage-users', function ($user) {
        return $user->role == 'admin' || $user->role == 'hr-manager';
    });
    
    $user = new User(1, 'hr-manager');
    
    if ($user->can('manage-users')) {
        echo "User can manage users";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_6() {
    // Gate definition with switch statement that always returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('edit-settings', function ($user) {
        switch ($user->role) {
            case 'admin':
                return true;
            case 'manager':
                return true;
            default:
                return false;
        }
    });
    
    $user = new User(1, 'manager');
    
    if ($user->can('edit-settings')) {
        echo "User can edit settings";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_7() {
    // Gate definition with try/catch that always returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('access-api', function ($user) {
        try {
            // Some logic that might throw an exception
            $hasAccess = $user->role == 'api-user' || $user->role == 'admin';
            return $hasAccess;
        } catch (Exception $e) {
            // Log error and deny access
            error_log($e->getMessage());
            return false;
        }
    });
    
    $user = new User(1, 'api-user');
    
    if ($user->can('access-api')) {
        echo "User can access API";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_8() {
    // Gate definition with early returns but always boolean
    // ok: php-insecure-gate-definition
    Gate::define('download-file', function ($user, $file) {
        // Premium users can download any file
        if ($user->role == 'premium') {
            return true;
        }
        
        // Free files can be downloaded by anyone
        if ($file->is_free) {
            return true;
        }
        
        // All other cases are denied
        return false;
    });
    
    $user = new User(1, 'basic');
    $file = (object)['is_free' => true];
    
    if ($user->can('download-file', $file)) {
        echo "User can download this file";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_9() {
    // Gate definition with boolean casting for safety
    // ok: php-insecure-gate-definition
    Gate::define('create-post', function ($user) {
        $canCreate = $user->role == 'editor' || $user->role == 'admin';
        return (bool) $canCreate; // Explicit boolean casting
    });
    
    $user = new User(1, 'editor');
    
    if ($user->can('create-post')) {
        echo "User can create posts";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_10() {
    // Gate definition with complex conditions but explicit boolean return
    // ok: php-insecure-gate-definition
    Gate::define('moderate-comments', function ($user, $comment) {
        $isModerator = $user->role == 'moderator';
        $isCommentAuthor = $comment->user_id == $user->id;
        $isAdmin = $user->role == 'admin';
        
        return $isModerator || $isCommentAuthor || $isAdmin;
    });
    
    $user = new User(1, 'moderator');
    $comment = (object)['user_id' => 2];
    
    if ($user->can('moderate-comments', $comment)) {
        echo "User can moderate this comment";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_11() {
    // Gate definition with helper function that returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('export-data', function ($user) {
        $checkPermission = function($userRole) {
            return $userRole == 'admin' || $userRole == 'data-analyst';
        };
        
        return $checkPermission($user->role);
    });
    
    $user = new User(1, 'data-analyst');
    
    if ($user->can('export-data')) {
        echo "User can export data";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_12() {
    // Gate definition with complex logic and explicit boolean returns
    // ok: php-insecure-gate-definition
    Gate::define('manage-project', function ($user, $project) {
        // Admin has full access
        if ($user->role == 'admin') {
            return true;
        }
        
        // Project owner has access
        if ($user->id == $project->owner_id) {
            return true;
        }
        
        // Project members have access
        if (in_array($user->id, $project->member_ids)) {
            return true;
        }
        
        // Everyone else is denied
        return false;
    });
    
    $user = new User(1, 'user');
    $project = (object)['owner_id' => 1, 'member_ids' => [3, 5]];
    
    if ($user->can('manage-project', $project)) {
        echo "User can manage this project";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_13() {
    // Gate definition with switch statement and default case
    // ok: php-insecure-gate-definition
    Gate::define('access-module', function ($user, $module) {
        switch ($user->role) {
            case 'admin':
                return true;
            case 'manager':
                return $module->managerAccessible === true;
            case 'user':
                return $module->publicAccess === true;
            default:
                return false;
        }
    });
    
    $user = new User(1, 'guest');
    $module = (object)['managerAccessible' => true, 'publicAccess' => false];
    
    if ($user->can('access-module', $module)) {
        echo "User can access this module";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_14() {
    // Gate definition with nested conditions but always returns boolean
    // ok: php-insecure-gate-definition
    Gate::define('process-payment', function ($user, $payment) {
        // Finance team can process any payment
        if ($user->role == 'finance') {
            return true;
        }
        
        // Users can process their own payments
        if ($user->id == $payment->user_id) {
            // Additional checks for user's own payments
            if ($payment->status == 'pending') {
                return true;
            } else {
                return false;
            }
        }
        
        // All other cases are denied
        return false;
    });
    
    $user = new User(1, 'user');
    $payment = (object)['user_id' => 1, 'status' => 'pending'];
    
    if ($user->can('process-payment', $payment)) {
        echo "User can process this payment";
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

function good_case_15() {
    // Gate definition with boolean logic operators
    // ok: php-insecure-gate-definition
    Gate::define('view-reports', function ($user, $report) {
        $isAdmin = $user->role == 'admin';
        $isAnalyst = $user->role == 'analyst';
        $isPublicReport = $report->is_public === true;
        $isReportOwner = $user->id == $report->owner_id;
        
        return $isAdmin || $isAnalyst || ($isPublicReport && $isReportOwner);
    });
    
    $user = new User(1, 'analyst');
    $report = (object)['is_public' => true, 'owner_id' => 2];
    
    if ($user->can('view-reports', $report)) {
        echo "User can view this report";
    }
}
// {/fact}
<?php
/**
 * Examples for php-editors-and-updates-security-sensitive rule
 * This rule detects when automatic WordPress updates are disabled
 */
// {fact rule=code-injection@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('automatic_updater_disabled', '__return_true');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_2() {
    // ruleid: php-editors-and-updates-security-sensitive
    define('AUTOMATIC_UPDATER_DISABLED', true);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_3() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_core', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_4() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('allow_minor_auto_core_updates', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_5() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('allow_major_auto_core_updates', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_6() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_plugin', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_7() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_theme', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_8() {
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_translation', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_9() {
    // Disabling all updates with a custom function
    function disable_all_updates() {
        return false;
    }
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_core', 'disable_all_updates');
    add_filter('auto_update_plugin', 'disable_all_updates');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_10() {
    // ruleid: php-editors-and-updates-security-sensitive
    define('WP_AUTO_UPDATE_CORE', false);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_11() {
    // ruleid: php-editors-and-updates-security-sensitive
    define('DISALLOW_FILE_MODS', true); // This prevents all updates and installations
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_12() {
    // Disabling updates conditionally
    if (is_admin()) {
        // ruleid: php-editors-and-updates-security-sensitive
        add_filter('auto_update_core', '__return_false');
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_13() {
    // ruleid: php-editors-and-updates-security-sensitive
    define('WP_AUTO_UPDATE_CORE', 'minor'); // Only allow minor updates, disabling major updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_14() {
    // Disabling updates with anonymous function
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('automatic_updater_disabled', function() {
        return true;
    });
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_15() {
    // Multiple update types disabled
    // ruleid: php-editors-and-updates-security-sensitive
    add_filter('auto_update_plugin', '__return_false');
    add_filter('auto_update_theme', '__return_false');
    add_filter('auto_update_translation', '__return_false');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('automatic_updater_disabled', '__return_false'); // Explicitly enabling automatic updater
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_2() {
    // ok: php-editors-and-updates-security-sensitive
    define('AUTOMATIC_UPDATER_DISABLED', false); // Explicitly not disabling automatic updater
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_3() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_core', '__return_true'); // Enabling core updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_4() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('allow_minor_auto_core_updates', '__return_true'); // Enabling minor core updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_5() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('allow_major_auto_core_updates', '__return_true'); // Enabling major core updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_6() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_plugin', '__return_true'); // Enabling plugin updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_7() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_theme', '__return_true'); // Enabling theme updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_8() {
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_translation', '__return_true'); // Enabling translation updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_9() {
    // Enabling all updates with a custom function
    function enable_all_updates() {
        return true;
    }
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_core', 'enable_all_updates');
    add_filter('auto_update_plugin', 'enable_all_updates');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_10() {
    // ok: php-editors-and-updates-security-sensitive
    define('WP_AUTO_UPDATE_CORE', true); // Enabling automatic core updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_11() {
    // ok: php-editors-and-updates-security-sensitive
    define('DISALLOW_FILE_MODS', false); // Not disabling file modifications
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_12() {
    // Enabling updates conditionally
    if (is_admin()) {
        // ok: php-editors-and-updates-security-sensitive
        add_filter('auto_update_core', '__return_true');
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_13() {
    // ok: php-editors-and-updates-security-sensitive
    define('WP_AUTO_UPDATE_CORE', true); // Enabling all updates
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_14() {
    // Enabling updates with anonymous function
    // ok: php-editors-and-updates-security-sensitive
    add_filter('automatic_updater_disabled', function() {
        return false;
    });
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_15() {
    // Selective update configuration (enabling important ones)
    // ok: php-editors-and-updates-security-sensitive
    add_filter('auto_update_plugin', '__return_true');
    
    // Custom logic for theme updates based on theme
    add_filter('auto_update_theme', function($update, $item) {
        // Only auto-update specific themes
        if ($item->theme == 'twentytwentyone') {
            return true;
        }
        return false;
    }, 10, 2);
}
// {/fact}
<?php
/**
 * Test cases for PHP Cross-Site Scripting (XSS) vulnerabilities
 * Rule ID: php-cross-site-scripting-ide
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}

// BAD CASES - Vulnerable to XSS

function bad_case_1() {
    // Direct output of GET parameter without sanitization
    $username = $_GET['username'];
    echo "Welcome, " . $username; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_2() {
    // POST data directly inserted into HTML
    $comment = $_POST['comment'];
    echo "<div class='comment'>" . $comment . "</div>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_3() {
    // Request parameter used in JavaScript
    $searchTerm = $_REQUEST['q'];
    echo "<script>var searchQuery = '" . $searchTerm . "';</script>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_4() {
    // Cookie value output directly
    $theme = $_COOKIE['theme'];
    echo "<body class='" . $theme . "'>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_5() {
    // HTTP header used unsafely
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    echo "Your browser: " . $userAgent; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_6() {
    // Input processed but still vulnerable
    $name = $_GET['name'];
    $name = strtoupper($name); // Processing that doesn't sanitize
    echo "<h1>Hello, " . $name . "!</h1>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_7() {
    // Multiple inputs combined
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    echo "Welcome, " . $firstName . " " . $lastName; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_8() {
    // Input used in HTML attribute
    $color = $_GET['color'];
    echo "<div style='color: " . $color . "'>Colored text</div>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_9() {
    // Input used in URL
    $redirect = $_GET['redirect'];
    echo "<a href='" . $redirect . "'>Click here</a>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_10() {
    // Input used in meta tag
    $keywords = $_POST['keywords'];
    echo "<meta name='keywords' content='" . $keywords . "'>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_11() {
    // Input used with string concatenation and variable interpolation
    $id = $_GET['id'];
    echo "<div id=\"user-{$id}\">User profile</div>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_12() {
    // Input used after some string manipulation
    $query = $_GET['query'];
    $query = str_replace("script", "", $query); // Inadequate sanitization
    echo "<p>You searched for: " . $query . "</p>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_13() {
    // Input used in conditional but still output unsafely
    $message = $_POST['message'];
    if (strlen($message) > 10) {
        $message = substr($message, 0, 10) . "..."; // Truncation doesn't sanitize
    }
    echo "<p class='message'>" . $message . "</p>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_14() {
    // Input used in JSON context
    $username = $_GET['username'];
    echo "<script>const user = { name: '" . $username . "' };</script>"; // ruleid: php-cross-site-scripting-ide
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_15() {
    // Input used after array manipulation
    $tags = explode(',', $_POST['tags']);
    foreach ($tags as $tag) {
        echo "<span class='tag'>" . $tag . "</span>"; // ruleid: php-cross-site-scripting-ide
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// GOOD CASES - Properly sanitized against XSS

function good_case_1() {
    // Proper sanitization with htmlspecialchars
    $username = $_GET['username'];
    // ok: php-cross-site-scripting-ide
    echo "Welcome, " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_2() {
    // Sanitizing POST data before inserting into HTML
    $comment = $_POST['comment'];
    // ok: php-cross-site-scripting-ide
    echo "<div class='comment'>" . htmlentities($comment, ENT_QUOTES, 'UTF-8') . "</div>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_3() {
    // Sanitizing request parameter used in JavaScript
    $searchTerm = $_REQUEST['q'];
    // ok: php-cross-site-scripting-ide
    echo "<script>var searchQuery = '" . json_encode($searchTerm) . "';</script>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_4() {
    // Sanitizing cookie value
    $theme = $_COOKIE['theme'];
    // ok: php-cross-site-scripting-ide
    echo "<body class='" . htmlspecialchars($theme, ENT_QUOTES, 'UTF-8') . "'>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_5() {
    // Sanitizing HTTP header
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ok: php-cross-site-scripting-ide
    echo "Your browser: " . htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_6() {
    // Input processed and properly sanitized
    $name = $_GET['name'];
    $name = strtoupper($name);
    // ok: php-cross-site-scripting-ide
    echo "<h1>Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_7() {
    // Multiple inputs combined with sanitization
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    // ok: php-cross-site-scripting-ide
    echo "Welcome, " . htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8') . " " . 
         htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_8() {
    // Input used in HTML attribute with sanitization
    $color = $_GET['color'];
    // Validate input is a valid color
    if (!preg_match('/^[a-zA-Z0-9#]+$/', $color)) {
        $color = 'black'; // Default safe value
    }
    // ok: php-cross-site-scripting-ide
    echo "<div style='color: " . htmlspecialchars($color, ENT_QUOTES, 'UTF-8') . "'>Colored text</div>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_9() {
    // Input used in URL with validation
    $redirect = $_GET['redirect'];
    // Validate URL
    if (filter_var($redirect, FILTER_VALIDATE_URL)) {
        // ok: php-cross-site-scripting-ide
        echo "<a href='" . htmlspecialchars($redirect, ENT_QUOTES, 'UTF-8') . "'>Click here</a>";
    } else {
        echo "<a href='index.php'>Click here</a>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_10() {
    // Input used in meta tag with sanitization
    $keywords = $_POST['keywords'];
    // ok: php-cross-site-scripting-ide
    echo "<meta name='keywords' content='" . htmlspecialchars($keywords, ENT_QUOTES, 'UTF-8') . "'>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_11() {
    // Input used with string concatenation and sanitization
    $id = $_GET['id'];
    // Ensure id is numeric
    if (!is_numeric($id)) {
        $id = 0; // Default safe value
    }
    // ok: php-cross-site-scripting-ide
    echo "<div id=\"user-" . $id . "\">User profile</div>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_12() {
    // Input properly sanitized
    $query = $_GET['query'];
    // ok: php-cross-site-scripting-ide
    echo "<p>You searched for: " . htmlspecialchars($query, ENT_QUOTES, 'UTF-8') . "</p>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_13() {
    // Input used in conditional with proper sanitization
    $message = $_POST['message'];
    if (strlen($message) > 10) {
        $message = substr($message, 0, 10) . "...";
    }
    // ok: php-cross-site-scripting-ide
    echo "<p class='message'>" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</p>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_14() {
    // Input used in JSON context with proper encoding
    $username = $_GET['username'];
    // ok: php-cross-site-scripting-ide
    echo "<script>const user = " . json_encode(['name' => $username]) . ";</script>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_15() {
    // Input used after array manipulation with sanitization
    $tags = explode(',', $_POST['tags']);
    foreach ($tags as $tag) {
        // ok: php-cross-site-scripting-ide
        echo "<span class='tag'>" . htmlspecialchars($tag, ENT_QUOTES, 'UTF-8') . "</span>";
    }
}
// {/fact}
?>
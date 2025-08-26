<?php
// {fact rule=autoescape-disabled@v1.0 defects=1}
// Test cases for php-echoed-request rule (CWE-79)

// BAD CASES - Vulnerable code that directly echoes user input

function bad_case_1() {
    // Direct echo of GET parameter without sanitization
    $username = $_GET['username'];
    // ruleid: php-echoed-request
    echo "Welcome, " . $username;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_2() {
    // Direct echo of POST parameter without sanitization
    $comment = $_POST['comment'];
    // ruleid: php-echoed-request
    echo $comment;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_3() {
    // Direct echo of REQUEST parameter without sanitization
    $searchTerm = $_REQUEST['search'];
    // ruleid: php-echoed-request
    echo "<div>Search results for: " . $searchTerm . "</div>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_4() {
    // Direct echo of COOKIE value without sanitization
    $theme = $_COOKIE['theme'];
    // ruleid: php-echoed-request
    echo "Current theme: " . $theme;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_5() {
    // Direct echo of HTTP header without sanitization
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: php-echoed-request
    echo "Your browser: " . $userAgent;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_6() {
    // Echo with string interpolation
    $email = $_POST['email'];
    // ruleid: php-echoed-request
    echo "Your email address is $email";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_7() {
    // Echo with concatenation and HTML context
    $productId = $_GET['id'];
    // ruleid: php-echoed-request
    echo "<input type='hidden' value='" . $productId . "' name='product_id'>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_8() {
    // Echo within a loop
    $ids = $_GET['ids'];
    $idArray = explode(',', $ids);
    foreach ($idArray as $id) {
        // ruleid: php-echoed-request
        echo "<li>Item #" . $id . "</li>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_9() {
    // Echo with conditional logic
    $message = $_GET['message'];
    if (strlen($message) > 0) {
        // ruleid: php-echoed-request
        echo "Message: " . $message;
    } else {
        echo "No message provided";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_10() {
    // Echo with string manipulation
    $name = $_POST['name'];
    $uppercaseName = strtoupper($name);
    // ruleid: php-echoed-request
    echo "Hello, " . $uppercaseName;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_11() {
    // Echo with print instead of echo
    $title = $_GET['title'];
    // ruleid: php-echoed-request
    print "Page title: " . $title;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_12() {
    // Echo with REQUEST_URI
    $uri = $_SERVER['REQUEST_URI'];
    // ruleid: php-echoed-request
    echo "You are viewing: " . $uri;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_13() {
    // Echo with array element
    $formData = $_POST['form'];
    // ruleid: php-echoed-request
    echo "Form name: " . $formData['name'];
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_14() {
    // Echo with HTTP_REFERER
    $referer = $_SERVER['HTTP_REFERER'];
    // ruleid: php-echoed-request
    echo "You came from: " . $referer;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_15() {
    // Echo with multiple concatenated inputs
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    // ruleid: php-echoed-request
    echo "Welcome, " . $firstName . " " . $lastName;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// GOOD CASES - Secure code that properly sanitizes user input

function good_case_1() {
    // Proper sanitization with htmlentities
    $username = $_GET['username'];
    // ok: php-echoed-request
    echo "Welcome, " . htmlentities($username, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_2() {
    // Proper sanitization with htmlspecialchars
    $comment = $_POST['comment'];
    // ok: php-echoed-request
    echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_3() {
    // Proper sanitization with REQUEST parameter
    $searchTerm = $_REQUEST['search'];
    // ok: php-echoed-request
    echo "<div>Search results for: " . htmlspecialchars($searchTerm, ENT_QUOTES, 'UTF-8') . "</div>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_4() {
    // Proper sanitization with COOKIE value
    $theme = $_COOKIE['theme'];
    // ok: php-echoed-request
    echo "Current theme: " . htmlentities($theme, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_5() {
    // Proper sanitization with HTTP header
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ok: php-echoed-request
    echo "Your browser: " . htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_6() {
    // Sanitization with string interpolation
    $email = $_POST['email'];
    $safeEmail = htmlentities($email, ENT_QUOTES, 'UTF-8');
    // ok: php-echoed-request
    echo "Your email address is $safeEmail";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_7() {
    // Sanitization in HTML attribute context
    $productId = $_GET['id'];
    // ok: php-echoed-request
    echo "<input type='hidden' value='" . htmlspecialchars($productId, ENT_QUOTES, 'UTF-8') . "' name='product_id'>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_8() {
    // Sanitization within a loop
    $ids = $_GET['ids'];
    $idArray = explode(',', $ids);
    foreach ($idArray as $id) {
        // ok: php-echoed-request
        echo "<li>Item #" . htmlentities($id, ENT_QUOTES, 'UTF-8') . "</li>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_9() {
    // Sanitization with conditional logic
    $message = $_GET['message'];
    if (strlen($message) > 0) {
        // ok: php-echoed-request
        echo "Message: " . htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    } else {
        echo "No message provided";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_10() {
    // Sanitization with string manipulation
    $name = $_POST['name'];
    $uppercaseName = strtoupper($name);
    // ok: php-echoed-request
    echo "Hello, " . htmlentities($uppercaseName, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_11() {
    // Using filter_var for sanitization
    $title = $_GET['title'];
    $safeTitle = filter_var($title, FILTER_SANITIZE_SPECIAL_CHARS);
    // ok: php-echoed-request
    echo "Page title: " . $safeTitle;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_12() {
    // Sanitization with REQUEST_URI
    $uri = $_SERVER['REQUEST_URI'];
    // ok: php-echoed-request
    echo "You are viewing: " . htmlspecialchars($uri, ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_13() {
    // Sanitization with array element
    $formData = $_POST['form'];
    // ok: php-echoed-request
    echo "Form name: " . htmlentities($formData['name'], ENT_QUOTES, 'UTF-8');
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_14() {
    // Using a dedicated sanitization function
    $referer = $_SERVER['HTTP_REFERER'];
    
    function sanitizeOutput($input) {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
    
    // ok: php-echoed-request
    echo "You came from: " . sanitizeOutput($referer);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_15() {
    // Sanitization with multiple concatenated inputs
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    // ok: php-echoed-request
    echo "Welcome, " . htmlentities($firstName, ENT_QUOTES, 'UTF-8') . " " . htmlentities($lastName, ENT_QUOTES, 'UTF-8');
}
// {/fact}
?>
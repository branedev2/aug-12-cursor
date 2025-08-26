<?php
// {fact rule=code-injection@v1.0 defects=1}

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Using assert with direct user input from GET parameter
    $userInput = $_GET['code'];
    // ruleid: php-assert-use
    assert($userInput);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_2() {
    // Using assert with user input from POST data
    $userInput = $_POST['expression'];
    // ruleid: php-assert-use
    assert("$userInput == 1");
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_3() {
    // Using assert with user input from REQUEST
    $userInput = $_REQUEST['test'];
    // ruleid: php-assert-use
    assert('return ' . $userInput . ';');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_4() {
    // Using assert with user input from COOKIE
    $userInput = $_COOKIE['debug'];
    // ruleid: php-assert-use
    assert($userInput . ' === true');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_5() {
    // Using assert with user input from HTTP header
    $userInput = getallheaders()['X-Custom-Header'];
    // ruleid: php-assert-use
    assert("function_exists('$userInput')");
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_6() {
    // Using assert with user input in a conditional
    $userInput = $_GET['condition'];
    if (strlen($userInput) > 5) {
        // ruleid: php-assert-use
        assert($userInput);
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_7() {
    // Using assert with user input after basic transformation
    $userInput = strtolower($_POST['command']);
    // ruleid: php-assert-use
    assert($userInput);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_8() {
    // Using assert with user input in a loop
    foreach ($_GET['tests'] as $test) {
        // ruleid: php-assert-use
        assert($test);
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_9() {
    // Using assert with user input from JSON
    $data = json_decode(file_get_contents('php://input'), true);
    $userInput = $data['expression'];
    // ruleid: php-assert-use
    assert($userInput);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_10() {
    // Using assert with user input after concatenation
    $userInput = $_GET['value'];
    $expression = 'return ' . $userInput . ' > 10;';
    // ruleid: php-assert-use
    assert($expression);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_11() {
    // Using assert with user input in a switch statement
    $userInput = $_POST['test_case'];
    switch ($userInput) {
        case 'test1':
            // ruleid: php-assert-use
            assert("1 + 1 == " . $_POST['expected']);
            break;
        default:
            echo "Unknown test";
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_12() {
    // Using assert with user input after array manipulation
    $inputs = $_REQUEST['inputs'];
    $expression = implode(' && ', $inputs);
    // ruleid: php-assert-use
    assert($expression);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_13() {
    // Using assert with user input from URL
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query'], $params);
    // ruleid: php-assert-use
    assert($params['condition']);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_14() {
    // Using assert with user input in a try-catch block
    try {
        $userInput = $_GET['expr'];
        // ruleid: php-assert-use
        assert($userInput);
    } catch (AssertionError $e) {
        echo "Assertion failed: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=1}

function bad_case_15() {
    // Using assert with user input after type casting
    $userInput = (string)$_POST['value'];
    // ruleid: php-assert-use
    assert("is_numeric($userInput) && $userInput > 0");
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

// True Negatives (Safe Code)

function good_case_1() {
    // Using assert with hardcoded string
    // ok: php-assert-use
    assert('1 == 1');
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_2() {
    // Using assert with hardcoded expression
    // ok: php-assert-use
    assert(true);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_3() {
    // Using assert with validated user input
    $userInput = $_GET['value'];
    if (in_array($userInput, ['true', 'false'])) {
        // ok: php-assert-use
        assert($userInput === 'true');
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_4() {
    // Using assert with sanitized user input
    $userInput = $_POST['number'];
    $sanitized = is_numeric($userInput) ? (int)$userInput : 0;
    // ok: php-assert-use
    assert($sanitized < 100);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_5() {
    // Using alternative validation method instead of assert
    $userInput = $_REQUEST['condition'];
    // ok: php-assert-use
    if (!eval("return $userInput;")) {
        throw new Exception("Condition failed");
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_6() {
    // Using proper validation function instead of assert
    $userInput = $_GET['value'];
    // ok: php-assert-use
    if (!is_numeric($userInput)) {
        throw new InvalidArgumentException("Value must be numeric");
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_7() {
    // Using assert with constant expression
    define('EXPECTED_VALUE', 42);
    // ok: php-assert-use
    assert(EXPECTED_VALUE === 42);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_8() {
    // Using assert in development environment only
    if (getenv('ENVIRONMENT') === 'development') {
        // ok: php-assert-use
        assert('count($array) > 0');
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_9() {
    // Using assert with computed but safe values
    $a = 5;
    $b = 10;
    // ok: php-assert-use
    assert($a + $b === 15);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_10() {
    // Using assert with function result
    function isValid() {
        return true;
    }
    // ok: php-assert-use
    assert(isValid());
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_11() {
    // Using assert with whitelist validation
    $userInput = $_POST['option'];
    $validOptions = ['a', 'b', 'c'];
    if (in_array($userInput, $validOptions)) {
        $option = $userInput;
    } else {
        $option = 'a';
    }
    // ok: php-assert-use
    assert("'$option' != ''");
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_12() {
    // Using assert with regex-validated input
    $userInput = $_GET['username'];
    if (preg_match('/^[a-zA-Z0-9]+$/', $userInput)) {
        // ok: php-assert-use
        assert("strlen('$userInput') > 0");
    }
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_13() {
    // Using assert with environment variables
    $debugMode = getenv('DEBUG_MODE');
    // ok: php-assert-use
    assert($debugMode !== false);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_14() {
    // Using assert with configuration values
    $config = [
        'max_users' => 100,
        'timeout' => 30
    ];
    // ok: php-assert-use
    assert($config['max_users'] > $config['timeout']);
}
// {/fact}
// {fact rule=code-injection@v1.0 defects=0}

function good_case_15() {
    // Using alternative assertion library
    $userInput = $_GET['value'];
    // ok: php-assert-use
    if (!is_numeric($userInput)) {
        throw new AssertionError("Value must be numeric");
    }
}
// {/fact}
?>
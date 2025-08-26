<?php
/**
 * Test cases for php-mb-ereg-replace-eval rule
 * This file contains examples of vulnerable and safe usage patterns
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Using mb_ereg_replace with 'e' modifier which allows code execution
    $user_input = $_GET['input'];
    $pattern = '/test/';
    $replacement = 'echo "Hello World";';
    // ruleid: php-mb-ereg-replace-eval
    $result = mb_ereg_replace($pattern, $replacement, $user_input, 'e');
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_2() {
    // Using mb_eregi_replace with 'e' modifier from POST data
    $data = $_POST['data'];
    $search = 'search_term';
    // ruleid: php-mb-ereg-replace-eval
    $output = mb_eregi_replace($search, 'system("ls")', $data, 'e');
    return $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_3() {
    // Using mb_ereg_replace with dynamic pattern and 'e' modifier
    $pattern = $_COOKIE['pattern'];
    $text = "This is a test string";
    // ruleid: php-mb-ereg-replace-eval
    $result = mb_ereg_replace($pattern, 'phpinfo()', $text, 'e');
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_4() {
    // Using mb_ereg_replace with 'e' modifier in a loop
    $inputs = $_REQUEST['inputs'];
    $pattern = 'test';
    foreach ($inputs as $input) {
        // ruleid: php-mb-ereg-replace-eval
        $processed = mb_ereg_replace($pattern, 'print("processed");', $input, 'e');
        echo $processed;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_5() {
    // Using mb_eregi_replace with 'e' modifier and concatenated replacement
    $user_data = $_GET['user_data'];
    $cmd = $_GET['cmd'];
    // ruleid: php-mb-ereg-replace-eval
    $result = mb_eregi_replace('pattern', 'system("' . $cmd . '")', $user_data, 'e');
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_6() {
    // Using mb_ereg_replace with 'e' modifier in a conditional
    $input = $_SERVER['HTTP_USER_AGENT'];
    if (strpos($input, 'Mozilla') !== false) {
        // ruleid: php-mb-ereg-replace-eval
        $processed = mb_ereg_replace('firefox', 'echo "Firefox detected";', $input, 'e');
        echo $processed;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_7() {
    // Using mb_ereg_replace with 'e' modifier and variable function
    $user_input = $_GET['text'];
    $func = 'system';
    // ruleid: php-mb-ereg-replace-eval
    $output = mb_ereg_replace('pattern', $func . '("whoami")', $user_input, 'e');
    echo $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_8() {
    // Using mb_eregi_replace with 'e' modifier in a switch statement
    $action = $_POST['action'];
    $content = $_POST['content'];
    
    switch ($action) {
        case 'process':
            // ruleid: php-mb-ereg-replace-eval
            $result = mb_eregi_replace('test', 'eval($_POST["code"])', $content, 'e');
            echo $result;
            break;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_9() {
    // Using mb_ereg_replace with 'e' modifier and complex pattern
    $html = $_POST['html'];
    $pattern = '<script>(.*?)</script>';
    // ruleid: php-mb-ereg-replace-eval
    $cleaned = mb_ereg_replace($pattern, 'echo "Script removed";', $html, 'e');
    echo $cleaned;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_10() {
    // Using mb_eregi_replace with 'e' modifier and header input
    $header = $_SERVER['HTTP_X_CUSTOM_HEADER'];
    // ruleid: php-mb-ereg-replace-eval
    $processed = mb_eregi_replace('test', 'include("' . $header . '.php")', "test string", 'e');
    echo $processed;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_11() {
    // Using mb_ereg_replace with 'e' modifier in a try-catch block
    try {
        $input = $_REQUEST['input'];
        // ruleid: php-mb-ereg-replace-eval
        $result = mb_ereg_replace('[0-9]+', 'echo $0 * 2;', $input, 'e');
        echo $result;
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_12() {
    // Using mb_eregi_replace with 'e' modifier and JSON input
    $json = json_decode($_POST['json'], true);
    $text = $json['text'];
    // ruleid: php-mb-ereg-replace-eval
    $output = mb_eregi_replace('pattern', 'file_get_contents("' . $text . '")', "test pattern", 'e');
    echo $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_13() {
    // Using mb_ereg_replace with 'e' modifier and multiple replacements
    $input = $_GET['input'];
    // ruleid: php-mb-ereg-replace-eval
    $step1 = mb_ereg_replace('pattern1', 'echo "step1";', $input, 'e');
    // ruleid: php-mb-ereg-replace-eval
    $step2 = mb_ereg_replace('pattern2', 'echo "step2";', $step1, 'e');
    echo $step2;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_14() {
    // Using mb_eregi_replace with 'e' modifier and variable options
    $input = $_COOKIE['data'];
    $options = 'e';
    // ruleid: php-mb-ereg-replace-eval
    $result = mb_eregi_replace('search', 'print_r($_SERVER)', $input, $options);
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_15() {
    // Using mb_ereg_replace with 'e' modifier in a callback
    $data = $_POST['data'];
    $callback = function($input) {
        // ruleid: php-mb-ereg-replace-eval
        return mb_ereg_replace('test', 'system("echo " . $input)', $input, 'e');
    };
    echo $callback($data);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Safe Code)

function good_case_1() {
    // Using preg_replace instead of mb_ereg_replace
    $user_input = $_GET['input'];
    $pattern = '/test/u';
    $replacement = 'replacement';
    // ok: php-mb-ereg-replace-eval
    $result = preg_replace($pattern, $replacement, $user_input);
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_2() {
    // Using mb_ereg_replace without 'e' modifier
    $data = $_POST['data'];
    $search = 'search_term';
    // ok: php-mb-ereg-replace-eval
    $output = mb_ereg_replace($search, 'replacement', $data);
    return $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_3() {
    // Using preg_replace with proper Unicode support
    $pattern = $_COOKIE['pattern'];
    $text = "This is a test string";
    // ok: php-mb-ereg-replace-eval
    $result = preg_replace('/' . preg_quote($pattern, '/') . '/u', 'replacement', $text);
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_4() {
    // Using preg_replace in a loop
    $inputs = $_REQUEST['inputs'];
    $pattern = '/test/u';
    foreach ($inputs as $input) {
        // ok: php-mb-ereg-replace-eval
        $processed = preg_replace($pattern, 'replacement', $input);
        echo $processed;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_5() {
    // Using preg_replace with proper escaping
    $user_data = $_GET['user_data'];
    $replacement = htmlspecialchars($_GET['replacement']);
    // ok: php-mb-ereg-replace-eval
    $result = preg_replace('/pattern/u', $replacement, $user_data);
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_6() {
    // Using preg_replace in a conditional
    $input = $_SERVER['HTTP_USER_AGENT'];
    if (strpos($input, 'Mozilla') !== false) {
        // ok: php-mb-ereg-replace-eval
        $processed = preg_replace('/firefox/ui', 'Firefox Browser', $input);
        echo $processed;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_7() {
    // Using str_replace as an alternative
    $user_input = $_GET['text'];
    // ok: php-mb-ereg-replace-eval
    $output = str_replace('pattern', 'replacement', $user_input);
    echo $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_8() {
    // Using preg_replace in a switch statement
    $action = $_POST['action'];
    $content = $_POST['content'];
    
    switch ($action) {
        case 'process':
            // ok: php-mb-ereg-replace-eval
            $result = preg_replace('/test/u', 'replacement', $content);
            echo $result;
            break;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_9() {
    // Using preg_replace for HTML sanitization
    $html = $_POST['html'];
    $pattern = '/<script>(.*?)<\/script>/u';
    // ok: php-mb-ereg-replace-eval
    $cleaned = preg_replace($pattern, '', $html);
    echo $cleaned;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_10() {
    // Using preg_replace with header input
    $header = $_SERVER['HTTP_X_CUSTOM_HEADER'];
    $safe_header = preg_replace('/[^a-zA-Z0-9_-]/u', '', $header);
    // ok: php-mb-ereg-replace-eval
    $processed = preg_replace('/test/u', $safe_header, "test string");
    echo $processed;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_11() {
    // Using preg_replace in a try-catch block
    try {
        $input = $_REQUEST['input'];
        // ok: php-mb-ereg-replace-eval
        $result = preg_replace_callback('/[0-9]+/u', function($matches) {
            return $matches[0] * 2;
        }, $input);
        echo $result;
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_12() {
    // Using preg_replace with JSON input
    $json = json_decode($_POST['json'], true);
    $text = $json['text'] ?? '';
    // ok: php-mb-ereg-replace-eval
    $output = preg_replace('/pattern/u', 'replacement', $text);
    echo $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_13() {
    // Using preg_replace with multiple replacements
    $input = $_GET['input'];
    // ok: php-mb-ereg-replace-eval
    $step1 = preg_replace('/pattern1/u', 'replacement1', $input);
    $step2 = preg_replace('/pattern2/u', 'replacement2', $step1);
    echo $step2;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_14() {
    // Using mb_ereg_replace with explicit non-eval option
    $input = $_COOKIE['data'];
    // ok: php-mb-ereg-replace-eval
    $result = mb_ereg_replace('search', 'replacement', $input, '');
    echo $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_15() {
    // Using preg_replace in a callback
    $data = $_POST['data'];
    $callback = function($input) {
        // ok: php-mb-ereg-replace-eval
        return preg_replace('/test/u', htmlspecialchars($input), $input);
    };
    echo $callback($data);
}
// {/fact}
?>
<?php
/**
 * Test cases for php-wp-code-execution-audit rule
 * CWE-94: Code Injection
 */

// TRUE POSITIVES - Vulnerable code examples

/**
 * Using eval() with user input from GET parameter
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    // Get user input directly from GET parameter
    $userCode = $_GET['code'];
    
    // ruleid: php-wp-code-execution-audit
    eval($userCode);
}
// {/fact}

/**
 * Using create_function() with user input from POST parameter
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    // Get user input from POST parameter
    $functionBody = $_POST['function_body'];
    
    // ruleid: php-wp-code-execution-audit
    $dynamicFunction = create_function('$arg', $functionBody);
    $dynamicFunction('test');
}
// {/fact}

/**
 * Using assert() with user input from REQUEST parameter
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    // Get user input from REQUEST parameter
    $condition = $_REQUEST['condition'];
    
    // ruleid: php-wp-code-execution-audit
    assert($condition);
}
// {/fact}

/**
 * Using call_user_func() with user input from COOKIE
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    // Get user input from cookie
    $functionName = $_COOKIE['function_name'];
    
    // ruleid: php-wp-code-execution-audit
    call_user_func($functionName, 'arg1', 'arg2');
}
// {/fact}

/**
 * Using call_user_func_array() with user input from HTTP header
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    // Get user input from HTTP header
    $headers = getallheaders();
    $functionName = $headers['X-Custom-Function'];
    $args = json_decode($headers['X-Custom-Args'], true);
    
    // ruleid: php-wp-code-execution-audit
    call_user_func_array($functionName, $args);
}
// {/fact}

/**
 * Using preg_replace with /e modifier and user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    // Get user input from GET parameter
    $replacement = $_GET['replacement'];
    $subject = "Hello, world!";
    
    // ruleid: php-wp-code-execution-audit
    preg_replace('/Hello, (.*)!/e', $replacement . '("\\1")', $subject);
}
// {/fact}

/**
 * Using include with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    // Get user input from GET parameter
    $template = $_GET['template'];
    
    // ruleid: php-wp-code-execution-audit
    include($template);
}
// {/fact}

/**
 * Using require_once with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    // Get user input from POST parameter
    $plugin = $_POST['plugin'];
    
    // ruleid: php-wp-code-execution-audit
    require_once($plugin);
}
// {/fact}

/**
 * Using system() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    // Get user input from GET parameter
    $command = $_GET['cmd'];
    
    // ruleid: php-wp-code-execution-audit
    system($command);
}
// {/fact}

/**
 * Using exec() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    // Get user input from POST parameter
    $command = $_POST['command'];
    
    // ruleid: php-wp-code-execution-audit
    exec($command, $output);
}
// {/fact}

/**
 * Using passthru() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    // Get user input from REQUEST parameter
    $command = $_REQUEST['shell_command'];
    
    // ruleid: php-wp-code-execution-audit
    passthru($command);
}
// {/fact}

/**
 * Using shell_exec() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    // Get user input from GET parameter
    $script = $_GET['script'];
    
    // ruleid: php-wp-code-execution-audit
    $output = shell_exec($script);
    echo $output;
}
// {/fact}

/**
 * Using popen() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    // Get user input from POST parameter
    $command = $_POST['command'];
    
    // ruleid: php-wp-code-execution-audit
    $handle = popen($command, 'r');
    $read = fread($handle, 2096);
    pclose($handle);
    echo $read;
}
// {/fact}

/**
 * Using extract() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    // Get user input from POST parameter
    $userVars = $_POST;
    
    // ruleid: php-wp-code-execution-audit
    extract($userVars);
    
    // Now variables from $_POST are in the local scope
    echo $potentially_dangerous_var;
}
// {/fact}

/**
 * Using unserialize() with user input
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    // Get user input from GET parameter
    $serializedData = $_GET['data'];
    
    // ruleid: php-wp-code-execution-audit
    $obj = unserialize($serializedData);
    echo $obj->property;
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

/**
 * Using eval() with hardcoded string (still not recommended but not a direct injection)
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    // Using hardcoded string instead of user input
    $code = 'return 1 + 1;';
    
    // ok: php-wp-code-execution-audit
    eval($code);
}
// {/fact}

/**
 * Validating user input before using create_function()
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    // Get user input from POST parameter
    $functionBody = $_POST['function_body'];
    
    // Validate input against a whitelist of allowed operations
    $allowedPatterns = array('/^return \d+ \+ \d+;$/', '/^return \d+ \* \d+;$/');
    $isValid = false;
    
    foreach ($allowedPatterns as $pattern) {
        if (preg_match($pattern, $functionBody)) {
            $isValid = true;
            break;
        }
    }
    
    if ($isValid) {
        // ok: php-wp-code-execution-audit
        $dynamicFunction = create_function('$arg', $functionBody);
        $dynamicFunction('test');
    } else {
        echo "Invalid function body";
    }
}
// {/fact}

/**
 * Using assert() with hardcoded condition
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    $value = 5;
    
    // ok: php-wp-code-execution-audit
    assert($value === 5);
}
// {/fact}

/**
 * Using call_user_func() with validated function name
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    // Get user input from cookie
    $functionName = $_COOKIE['function_name'];
    
    // Validate against whitelist of allowed functions
    $allowedFunctions = array('htmlspecialchars', 'trim', 'strtoupper');
    
    if (in_array($functionName, $allowedFunctions)) {
        // ok: php-wp-code-execution-audit
        call_user_func($functionName, 'test string');
    } else {
        echo "Function not allowed";
    }
}
// {/fact}

/**
 * Using call_user_func_array() with hardcoded function name
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    // Get arguments from user input but function name is hardcoded
    $args = json_decode($_POST['args'], true);
    
    // Validate arguments
    $args = array_map('sanitize_text_field', $args);
    
    // ok: php-wp-code-execution-audit
    call_user_func_array('implode', $args);
}
// {/fact}

/**
 * Using preg_replace without /e modifier
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    // Get user input from GET parameter
    $replacement = $_GET['replacement'];
    $subject = "Hello, world!";
    
    // Sanitize the replacement string
    $replacement = htmlspecialchars($replacement);
    
    // ok: php-wp-code-execution-audit
    $result = preg_replace('/Hello, (.*)!/', $replacement . ' \\1', $subject);
}
// {/fact}

/**
 * Using include with validated path
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    // Get user input from GET parameter
    $template = $_GET['template'];
    
    // Validate against whitelist of allowed templates
    $allowedTemplates = array(
        'header.php',
        'footer.php',
        'sidebar.php'
    );
    
    if (in_array($template, $allowedTemplates)) {
        // ok: php-wp-code-execution-audit
        include(TEMPLATE_PATH . '/' . $template);
    } else {
        echo "Template not allowed";
    }
}
// {/fact}

/**
 * Using require_once with validated path
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    // Get user input from POST parameter
    $plugin = $_POST['plugin'];
    
    // Validate plugin path using realpath to prevent directory traversal
    $pluginPath = realpath(PLUGIN_DIR . '/' . $plugin . '/main.php');
    $pluginDir = realpath(PLUGIN_DIR);
    
    // Check if the path is within the plugins directory
    if ($pluginPath && strpos($pluginPath, $pluginDir) === 0 && file_exists($pluginPath)) {
        // ok: php-wp-code-execution-audit
        require_once($pluginPath);
    } else {
        echo "Invalid plugin";
    }
}
// {/fact}

/**
 * Using system() with validated command
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    // Get user input from GET parameter
    $filename = $_GET['filename'];
    
    // Sanitize filename to prevent command injection
    $filename = escapeshellarg(basename($filename));
    
    // ok: php-wp-code-execution-audit
    system('ls ' . $filename);
}
// {/fact}

/**
 * Using exec() with validated input
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    // Get user input from POST parameter
    $userId = (int)$_POST['user_id'];
    
    // Ensure it's a valid integer
    if ($userId > 0) {
        // ok: php-wp-code-execution-audit
        exec('get_user_data.sh ' . $userId, $output);
    } else {
        echo "Invalid user ID";
    }
}
// {/fact}

/**
 * Using passthru() with hardcoded command
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    // No user input used in the command
    $command = 'ls -la /var/www/html/public';
    
    // ok: php-wp-code-execution-audit
    passthru($command);
}
// {/fact}

/**
 * Using shell_exec() with validated input
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    // Get user input from GET parameter
    $year = $_GET['year'];
    
    // Validate year is a 4-digit number
    if (preg_match('/^[0-9]{4}$/', $year)) {
        // ok: php-wp-code-execution-audit
        $output = shell_exec('get_reports.sh ' . escapeshellarg($year));
        echo $output;
    } else {
        echo "Invalid year format";
    }
}
// {/fact}

/**
 * Using popen() with validated input
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    // Get user input from POST parameter
    $filename = $_POST['filename'];
    
    // Validate filename
    if (preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename)) {
        // ok: php-wp-code-execution-audit
        $handle = popen('cat ' . escapeshellarg($filename), 'r');
        $read = fread($handle, 2096);
        pclose($handle);
        echo $read;
    } else {
        echo "Invalid filename";
    }
}
// {/fact}

/**
 * Using extract() with filtered input
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    // Get user input from POST parameter
    $userVars = array_map('sanitize_text_field', $_POST);
    
    // Define allowed keys
    $allowedKeys = array('name', 'email', 'subject');
    
    // Filter to only include allowed keys
    $filteredVars = array_intersect_key($userVars, array_flip($allowedKeys));
    
    // ok: php-wp-code-execution-audit
    extract($filteredVars, EXTR_SKIP);
    
    echo "Name: " . (isset($name) ? $name : '') . "<br>";
    echo "Email: " . (isset($email) ? $email : '') . "<br>";
}
// {/fact}

/**
 * Using unserialize() with validation
 */
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    // Get user input from GET parameter
    $serializedData = $_GET['data'];
    
    // Validate the serialized data structure before unserializing
    if (preg_match('/^a:[0-9]+:{(s:[0-9]+:"[^"]+";[ibsaO]:[0-9.E-]+;)+}$/', $serializedData)) {
        // ok: php-wp-code-execution-audit
        $data = unserialize($serializedData);
        
        // Further validate the unserialized data
        foreach ($data as $key => $value) {
            echo htmlspecialchars($key) . ': ' . htmlspecialchars((string)$value) . '<br>';
        }
    } else {
        echo "Invalid data format";
    }
}
// {/fact}
?>
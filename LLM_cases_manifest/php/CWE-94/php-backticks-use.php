<?php
/**
 * Test cases for php-backticks-use rule
 * This rule detects potential command injection vulnerabilities through backtick usage
 */
// {fact rule=autoescape-disabled@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable code examples)

function bad_case_1() {
    // Command injection via GET parameter using backticks
    $command = $_GET['command'];
    // ruleid: php-backticks-use
    $output = `$command`;
    echo "Command output: " . $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_2() {
    // Command injection via POST parameter using backticks
    $userInput = $_POST['userInput'];
    // ruleid: php-backticks-use
    $result = `ls -la $userInput`;
    echo "Directory listing: " . $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_3() {
    // Command injection via REQUEST parameter using backticks
    $filename = $_REQUEST['filename'];
    // ruleid: php-backticks-use
    $fileInfo = `file $filename`;
    echo "File information: " . $fileInfo;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_4() {
    // Command injection via HTTP header using backticks
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: php-backticks-use
    $logResult = `echo "$userAgent" >> /tmp/user_agents.log`;
    echo "Logged user agent";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_5() {
    // Command injection via COOKIE using backticks
    $sessionId = $_COOKIE['session_id'];
    // ruleid: php-backticks-use
    $checkResult = `grep "$sessionId" /var/log/sessions.log`;
    return !empty($checkResult);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_6() {
    // Command injection with string concatenation using backticks
    $searchTerm = $_GET['search'];
    $command = "find /var/www -name '*" . $searchTerm . "*'";
    // ruleid: php-backticks-use
    $files = `$command`;
    echo "Found files: " . $files;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_7() {
    // Command injection with variable interpolation in backticks
    $path = $_POST['path'];
    // ruleid: php-backticks-use
    $dirSize = `du -sh $path`;
    echo "Directory size: " . $dirSize;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_8() {
    // Command injection with multiple commands using backticks
    $username = $_GET['username'];
    // ruleid: php-backticks-use
    $userInfo = `id $username && ls -la /home/$username`;
    echo "User information: " . $userInfo;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_9() {
    // Command injection in a conditional statement using backticks
    $ip = $_SERVER['REMOTE_ADDR'];
    if (strlen($ip) > 0) {
        // ruleid: php-backticks-use
        $pingResult = `ping -c 1 $ip`;
        echo "Ping result: " . $pingResult;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_10() {
    // Command injection in a loop using backticks
    $files = explode(',', $_POST['files']);
    $results = [];
    foreach ($files as $file) {
        // ruleid: php-backticks-use
        $results[] = `stat $file`;
    }
    echo implode("<br>", $results);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_11() {
    // Command injection with partial sanitization (still vulnerable) using backticks
    $domain = str_replace(['|', '&', ';'], '', $_GET['domain']);
    // ruleid: php-backticks-use
    $whoisInfo = `whois $domain`;
    echo "WHOIS information: " . $whoisInfo;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_12() {
    // Command injection with ternary operator using backticks
    $option = isset($_GET['option']) ? $_GET['option'] : 'default';
    // ruleid: php-backticks-use
    $result = `echo $option`;
    echo "Selected option: " . $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_13() {
    // Command injection with switch statement using backticks
    $action = $_POST['action'];
    switch ($action) {
        case 'list':
            $dir = $_POST['directory'];
            // ruleid: php-backticks-use
            $listing = `ls -la $dir`;
            echo $listing;
            break;
        default:
            echo "Unknown action";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_14() {
    // Command injection with array input using backticks
    $server = $_POST['server'];
    $port = $_POST['port'];
    // ruleid: php-backticks-use
    $netstatResult = `netstat -an | grep $server:$port`;
    echo "Connection status: " . $netstatResult;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_15() {
    // Command injection with try-catch using backticks
    try {
        $query = $_GET['query'];
        // ruleid: php-backticks-use
        $searchResult = `grep -r "$query" /var/www/html`;
        echo "Search results: " . $searchResult;
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// TRUE NEGATIVES (Safe code examples)

function good_case_1() {
    // Safe alternative using escapeshellcmd and escapeshellarg
    $command = $_GET['command'];
    $safeCommand = escapeshellcmd($command);
    // ok: php-backticks-use
    $output = shell_exec("echo " . escapeshellarg($safeCommand));
    echo "Command output: " . $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_2() {
    // Safe alternative using exec instead of backticks
    $userInput = $_POST['userInput'];
    $safeInput = escapeshellarg($userInput);
    // ok: php-backticks-use
    exec("ls -la $safeInput", $result);
    echo "Directory listing: " . implode("\n", $result);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_3() {
    // Safe alternative using system instead of backticks
    $filename = $_REQUEST['filename'];
    $safeFilename = escapeshellarg($filename);
    // ok: php-backticks-use
    system("file $safeFilename", $returnVal);
    echo "Return value: " . $returnVal;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_4() {
    // Safe alternative using passthru instead of backticks
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $safeAgent = escapeshellarg($userAgent);
    // ok: php-backticks-use
    passthru("echo $safeAgent >> /tmp/user_agents.log");
    echo "Logged user agent";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_5() {
    // Safe alternative using proc_open instead of backticks
    $sessionId = $_COOKIE['session_id'];
    $safeSessionId = escapeshellarg($sessionId);
    
    // ok: php-backticks-use
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"]
    ];
    $process = proc_open("grep $safeSessionId /var/log/sessions.log", $descriptorspec, $pipes);
    
    if (is_resource($process)) {
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);
        return !empty($output);
    }
    return false;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_6() {
    // Using a whitelist approach for command execution
    $action = $_GET['action'];
    $allowedActions = ['list', 'count', 'find'];
    
    if (in_array($action, $allowedActions)) {
        $dir = '/var/www/html';
        // ok: php-backticks-use
        $output = shell_exec("ls -la $dir");
        echo "Directory contents: " . $output;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_7() {
    // Using a predefined command with no user input
    // ok: php-backticks-use
    $serverLoad = shell_exec("uptime");
    echo "Server load: " . $serverLoad;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_8() {
    // Using a safer alternative with input validation
    $username = $_GET['username'];
    if (preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        // ok: php-backticks-use
        exec("id " . escapeshellarg($username), $output);
        echo "User information: " . implode("\n", $output);
    } else {
        echo "Invalid username format";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_9() {
    // Using a safer alternative in a conditional statement
    $ip = $_SERVER['REMOTE_ADDR'];
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        // ok: php-backticks-use
        exec("ping -c 1 " . escapeshellarg($ip), $pingResult);
        echo "Ping result: " . implode("\n", $pingResult);
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_10() {
    // Using a safer alternative in a loop
    $files = explode(',', $_POST['files']);
    $results = [];
    foreach ($files as $file) {
        $safeFile = escapeshellarg($file);
        // ok: php-backticks-use
        exec("stat $safeFile", $output);
        $results[] = implode("\n", $output);
    }
    echo implode("<br>", $results);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_11() {
    // Using a safer alternative with proper input sanitization
    $domain = $_GET['domain'];
    if (preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain)) {
        // ok: php-backticks-use
        $output = shell_exec("whois " . escapeshellarg($domain));
        echo "WHOIS information: " . $output;
    } else {
        echo "Invalid domain format";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_12() {
    // Using a safer alternative with ternary operator
    $option = isset($_GET['option']) ? $_GET['option'] : 'default';
    $safeOption = escapeshellarg($option);
    // ok: php-backticks-use
    $result = shell_exec("echo $safeOption");
    echo "Selected option: " . $result;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_13() {
    // Using a safer alternative with switch statement
    $action = $_POST['action'];
    switch ($action) {
        case 'list':
            $dir = $_POST['directory'];
            $safeDir = escapeshellarg($dir);
            // ok: php-backticks-use
            exec("ls -la $safeDir", $listing);
            echo implode("\n", $listing);
            break;
        default:
            echo "Unknown action";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_14() {
    // Using a safer alternative with array input
    $server = $_POST['server'];
    $port = $_POST['port'];
    
    if (filter_var($server, FILTER_VALIDATE_IP) && is_numeric($port)) {
        $safeServer = escapeshellarg($server);
        $safePort = escapeshellarg($port);
        // ok: php-backticks-use
        exec("netstat -an | grep $safeServer:$safePort", $result);
        echo "Connection status: " . implode("\n", $result);
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_15() {
    // Using a safer alternative with try-catch
    try {
        $query = $_GET['query'];
        $safeQuery = escapeshellarg($query);
        // ok: php-backticks-use
        exec("grep -r $safeQuery /var/www/html", $searchResult);
        echo "Search results: " . implode("\n", $searchResult);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
?>
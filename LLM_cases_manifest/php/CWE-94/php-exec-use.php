<?php
// PHP Command Injection Vulnerability Test Cases
// {fact rule=autoescape-disabled@v1.0 defects=1}
// Rule ID: php-exec-use
// CWE-94: Improper Control of Generation of Code ('Code Injection')

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Command injection via GET parameter
    $command = $_GET['command'];
    // ruleid: php-exec-use
    system($command);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_2() {
    // Command injection via POST parameter with concatenation
    $filename = $_POST['filename'];
    // ruleid: php-exec-use
    exec("ls -la " . $filename);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_3() {
    // Command injection via REQUEST parameter with string interpolation
    $dir = $_REQUEST['directory'];
    // ruleid: php-exec-use
    shell_exec("find $dir -type f -name '*.php'");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_4() {
    // Command injection via COOKIE with passthru
    $param = $_COOKIE['param'];
    // ruleid: php-exec-use
    passthru("grep -r '$param' /var/www/html/");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_5() {
    // Command injection via SERVER variable
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: php-exec-use
    system("echo $userAgent > /tmp/user_agents.log");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_6() {
    // Command injection with multiple parameters and backticks
    $search = $_GET['search'];
    $dir = $_GET['dir'];
    // ruleid: php-exec-use
    $output = `find $dir -name "*$search*"`;
    echo $output;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_7() {
    // Command injection with variable processing before use
    $input = $_POST['input'];
    $command = "grep " . $input . " /var/log/apache2/access.log";
    // ruleid: php-exec-use
    exec($command, $output, $return_var);
    foreach ($output as $line) {
        echo $line . "<br>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_8() {
    // Command injection with conditional execution
    $action = $_GET['action'];
    $target = $_GET['target'];
    
    if ($action === "backup") {
        // ruleid: php-exec-use
        system("tar -czf /backups/backup.tar.gz $target");
    } else {
        echo "Invalid action";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_9() {
    // Command injection with proc_open
    $cmd = $_POST['command'];
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );
    // ruleid: php-exec-use
    $process = proc_open($cmd, $descriptorspec, $pipes);
    
    if (is_resource($process)) {
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);
        echo $output;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_10() {
    // Command injection with popen
    $file = $_GET['file'];
    // ruleid: php-exec-use
    $handle = popen("cat $file", "r");
    
    if ($handle) {
        while (!feof($handle)) {
            echo fread($handle, 8192);
        }
        pclose($handle);
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_11() {
    // Command injection with multiple inputs combined
    $username = $_POST['username'];
    $domain = $_POST['domain'];
    // ruleid: php-exec-use
    exec("whois $domain | grep $username", $output);
    print_r($output);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_12() {
    // Command injection with array input
    $files = $_POST['files'];
    $command = "zip archive.zip";
    
    foreach ($files as $file) {
        $command .= " " . $file;
    }
    
    // ruleid: php-exec-use
    system($command);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_13() {
    // Command injection with JSON input
    $data = json_decode(file_get_contents('php://input'), true);
    $command = $data['command'];
    $args = $data['arguments'];
    
    // ruleid: php-exec-use
    exec("$command $args", $output);
    echo json_encode($output);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_14() {
    // Command injection with input filtering attempt that can be bypassed
    $input = $_GET['input'];
    $filtered = str_replace(';', '', $input); // Insufficient filtering
    
    // ruleid: php-exec-use
    system("echo $filtered > /tmp/output.txt");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

function bad_case_15() {
    // Command injection with shell_exec and HTTP header
    $referer = $_SERVER['HTTP_REFERER'];
    // ruleid: php-exec-use
    $output = shell_exec("curl -I $referer");
    echo "<pre>$output</pre>";
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

function good_case_1() {
    // Safe execution using escapeshellarg for GET parameter
    $command = $_GET['command'];
    // ok: php-exec-use
    system("ls " . escapeshellarg($command));
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_2() {
    // Safe execution using escapeshellcmd and escapeshellarg
    $cmd = $_POST['cmd'];
    $arg = $_POST['arg'];
    // ok: php-exec-use
    exec(escapeshellcmd($cmd) . " " . escapeshellarg($arg), $output);
    print_r($output);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_3() {
    // Safe execution using whitelist validation
    $allowed_commands = ['ls', 'pwd', 'whoami'];
    $command = $_REQUEST['command'];
    
    if (in_array($command, $allowed_commands)) {
        // ok: php-exec-use
        shell_exec($command);
    } else {
        echo "Command not allowed";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_4() {
    // Safe execution using proc_open with validated input
    $file = $_GET['file'];
    $allowed_files = ['report.txt', 'log.txt', 'data.csv'];
    
    if (in_array($file, $allowed_files)) {
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        // ok: php-exec-use
        $process = proc_open("cat " . escapeshellarg($file), $descriptorspec, $pipes);
        
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            proc_close($process);
            echo $output;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_5() {
    // Safe execution with hardcoded commands
    // ok: php-exec-use
    system("ls -la /var/www/html");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_6() {
    // Safe execution using alternative PHP functions
    $filename = $_POST['filename'];
    $allowed_dirs = ['/var/www/uploads/', '/tmp/'];
    $safe = false;
    
    foreach ($allowed_dirs as $dir) {
        if (strpos(realpath($filename), $dir) === 0) {
            $safe = true;
            break;
        }
    }
    
    if ($safe && file_exists($filename)) {
        // ok: php-exec-use
        $contents = file_get_contents($filename);
        echo $contents;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_7() {
    // Safe execution with proper input validation and sanitization
    $search = $_GET['search'];
    if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $search)) {
        die("Invalid search parameter");
    }
    
    // ok: php-exec-use
    exec("find /var/www/html -name " . escapeshellarg("*$search*"), $output);
    foreach ($output as $line) {
        echo htmlspecialchars($line) . "<br>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_8() {
    // Safe execution using PHP's built-in functions instead of shell commands
    $dir = $_POST['directory'];
    $safeDir = realpath($dir);
    
    if ($safeDir && is_dir($safeDir) && strpos($safeDir, '/var/www/') === 0) {
        // ok: php-exec-use
        $files = scandir($safeDir);
        foreach ($files as $file) {
            echo htmlspecialchars($file) . "<br>";
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_9() {
    // Safe execution with environment variables
    $env = [
        'PATH' => '/usr/local/bin:/usr/bin:/bin',
        'USER' => 'www-data'
    ];
    
    // ok: php-exec-use
    $process = proc_open('ls -la', [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ], $pipes, '/var/www/html', $env);
    
    if (is_resource($process)) {
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);
        echo $output;
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_10() {
    // Safe execution with predefined command options
    $option = $_GET['option'];
    $validOptions = [
        'list' => 'ls -la',
        'disk' => 'df -h',
        'memory' => 'free -m'
    ];
    
    if (isset($validOptions[$option])) {
        // ok: php-exec-use
        exec($validOptions[$option], $output);
        foreach ($output as $line) {
            echo htmlspecialchars($line) . "<br>";
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_11() {
    // Safe execution with parameter binding for database operations instead of shell commands
    $search = $_POST['search'];
    
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'user', 'password');
    // ok: php-exec-use
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username LIKE :search");
    $stmt->bindValue(':search', "%$search%", PDO::PARAM_STR);
    $stmt->execute();
    
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($results as $row) {
        echo htmlspecialchars($row['username']) . "<br>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_12() {
    // Safe execution with JSON operations instead of shell commands
    $data = $_POST['data'];
    $jsonData = json_decode($data, true);
    
    if (json_last_error() === JSON_ERROR_NONE) {
        // ok: php-exec-use
        $result = [
            'status' => 'success',
            'count' => count($jsonData),
            'processed' => true
        ];
        echo json_encode($result);
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_13() {
    // Safe execution with file operations instead of shell commands
    $filename = $_GET['filename'];
    $safePath = '/var/www/uploads/';
    $fullPath = $safePath . basename($filename); // Prevent directory traversal
    
    if (file_exists($fullPath)) {
        // ok: php-exec-use
        $filesize = filesize($fullPath);
        $modified = date("Y-m-d H:i:s", filemtime($fullPath));
        
        echo "File: " . htmlspecialchars(basename($fullPath)) . "<br>";
        echo "Size: $filesize bytes<br>";
        echo "Modified: $modified<br>";
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_14() {
    // Safe execution with proper configuration and validation
    $action = $_REQUEST['action'];
    $allowedActions = ['backup', 'restore', 'status'];
    
    if (in_array($action, $allowedActions)) {
        $configFile = '/etc/app/config.json';
        $config = json_decode(file_get_contents($configFile), true);
        
        // ok: php-exec-use
        $scriptPath = $config['scripts_path'] . '/' . $action . '.sh';
        if (file_exists($scriptPath)) {
            exec(escapeshellcmd($scriptPath), $output);
            echo implode("<br>", array_map('htmlspecialchars', $output));
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

function good_case_15() {
    // Safe execution with complete input validation and sanitization
    $input = $_POST['input'];
    
    // Validate input format (alphanumeric only)
    if (!preg_match('/^[a-zA-Z0-9]+$/', $input)) {
        die("Invalid input format");
    }
    
    // Use a predefined command with sanitized input
    $command = sprintf(
        'grep -c %s /var/log/app.log',
        escapeshellarg($input)
    );
    
    // ok: php-exec-use
    exec($command, $output, $return_var);
    
    if ($return_var === 0) {
        echo "Found " . intval($output[0]) . " occurrences";
    } else {
        echo "Search failed";
    }
}
// {/fact}
?>
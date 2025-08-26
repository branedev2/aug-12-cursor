<?php
/**
 * Test cases for PHP OS Command Injection vulnerability detection
 * Rule ID: php-os-command-injection
 * CWE: CWE-78
 */
// {fact rule=os-command-injection@v1.0 defects=1}

// ======== TRUE POSITIVES (VULNERABLE CODE) ========

function bad_case_1() {
    // Direct command injection from GET parameter
    $command = $_GET['cmd'];
    // ruleid: php-os-command-injection
    exec($command);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_2() {
    // Command injection with string concatenation
    $filename = $_POST['filename'];
    // ruleid: php-os-command-injection
    system("ls -la " . $filename);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_3() {
    // Command injection using shell_exec
    $username = $_REQUEST['user'];
    // ruleid: php-os-command-injection
    $output = shell_exec("grep $username /etc/passwd");
    echo $output;
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_4() {
    // Command injection with passthru
    $ip = $_GET['ip'];
    // ruleid: php-os-command-injection
    passthru("ping -c 4 $ip");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_5() {
    // Command injection with backticks
    $domain = $_POST['domain'];
    // ruleid: php-os-command-injection
    $output = `nslookup $domain`;
    echo $output;
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_6() {
    // Command injection with variable interpolation
    $file = $_GET['file'];
    $command = "cat $file";
    // ruleid: php-os-command-injection
    system($command);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_7() {
    // Command injection with HTTP header
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: php-os-command-injection
    exec("echo $userAgent > /tmp/user_agents.log");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_8() {
    // Command injection with cookie data
    $theme = $_COOKIE['theme'];
    // ruleid: php-os-command-injection
    shell_exec("convert -theme $theme input.jpg output.jpg");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_9() {
    // Command injection with multiple parameters
    $date = $_GET['date'];
    $format = $_GET['format'];
    // ruleid: php-os-command-injection
    system("date -d \"$date\" +\"$format\"");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_10() {
    // Command injection with minimal processing
    $command = trim($_POST['cmd']);
    // ruleid: php-os-command-injection
    passthru($command);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_11() {
    // Command injection with string replacement
    $search = $_GET['search'];
    $search = str_replace('"', '', $search); // Insufficient sanitization
    // ruleid: php-os-command-injection
    exec("grep -i \"$search\" /var/log/app.log");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_12() {
    // Command injection with proc_open
    $dir = $_POST['directory'];
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );
    // ruleid: php-os-command-injection
    $process = proc_open("ls -la $dir", $descriptorspec, $pipes);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_13() {
    // Command injection with popen
    $query = $_GET['query'];
    // ruleid: php-os-command-injection
    $handle = popen("whois $query", "r");
    while (!feof($handle)) {
        echo fread($handle, 1024);
    }
    pclose($handle);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_14() {
    // Command injection with complex string building
    $sort = $_GET['sort'];
    $order = $_GET['order'];
    $command = "ls";
    if ($sort) {
        $command .= " --sort=$sort";
    }
    if ($order) {
        $command .= " --$order";
    }
    // ruleid: php-os-command-injection
    system($command);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

function bad_case_15() {
    // Command injection with JSON input
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    $command = $data['command'];
    // ruleid: php-os-command-injection
    exec($command, $output);
    echo json_encode($output);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// ======== TRUE NEGATIVES (SAFE CODE) ========

function good_case_1() {
    // Using escapeshellarg for safe command execution
    $filename = $_GET['filename'];
    $safe_filename = escapeshellarg($filename);
    // ok: php-os-command-injection
    system("ls -la $safe_filename");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_2() {
    // Using escapeshellcmd for safe command execution
    $command = $_POST['command'];
    $safe_command = escapeshellcmd($command);
    // ok: php-os-command-injection
    exec($safe_command);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_3() {
    // Using constant command with no user input
    // ok: php-os-command-injection
    system("ls -la /var/www/html");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_4() {
    // Using whitelist validation
    $action = $_GET['action'];
    $allowed_actions = ['list', 'count', 'find'];
    
    if (in_array($action, $allowed_actions)) {
        // ok: php-os-command-injection
        exec("git $action");
    } else {
        echo "Invalid action";
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_5() {
    // Using escapeshellarg with shell_exec
    $domain = $_POST['domain'];
    $safe_domain = escapeshellarg($domain);
    // ok: php-os-command-injection
    $output = shell_exec("nslookup $safe_domain");
    echo $output;
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_6() {
    // Using built-in PHP functions instead of shell commands
    $filename = $_GET['filename'];
    // ok: php-os-command-injection
    if (file_exists($filename)) {
        $content = file_get_contents($filename);
        echo $content;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_7() {
    // Using escapeshellarg with passthru
    $ip = $_GET['ip'];
    $safe_ip = escapeshellarg($ip);
    // ok: php-os-command-injection
    passthru("ping -c 4 $safe_ip");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_8() {
    // Using escapeshellarg with backticks
    $username = $_REQUEST['user'];
    $safe_username = escapeshellarg($username);
    // ok: php-os-command-injection
    $output = `grep $safe_username /etc/passwd`;
    echo $output;
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_9() {
    // Using proc_open with escapeshellarg
    $dir = $_POST['directory'];
    $safe_dir = escapeshellarg($dir);
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );
    // ok: php-os-command-injection
    $process = proc_open("ls -la $safe_dir", $descriptorspec, $pipes);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_10() {
    // Using popen with escapeshellarg
    $query = $_GET['query'];
    $safe_query = escapeshellarg($query);
    // ok: php-os-command-injection
    $handle = popen("whois $safe_query", "r");
    while (!feof($handle)) {
        echo fread($handle, 1024);
    }
    pclose($handle);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_11() {
    // Using regex pattern matching for validation
    $date = $_GET['date'];
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        // ok: php-os-command-injection
        system("date -d \"$date\" +\"%Y-%m-%d\"");
    } else {
        echo "Invalid date format";
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_12() {
    // Using both escapeshellcmd and escapeshellarg
    $command = $_POST['cmd'];
    $arg = $_POST['arg'];
    $safe_command = escapeshellcmd($command);
    $safe_arg = escapeshellarg($arg);
    // ok: php-os-command-injection
    exec("$safe_command $safe_arg");
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_13() {
    // Using switch statement for command selection
    $action = $_GET['action'];
    switch ($action) {
        case 'list':
            // ok: php-os-command-injection
            system("ls -la");
            break;
        case 'disk':
            // ok: php-os-command-injection
            system("df -h");
            break;
        case 'memory':
            // ok: php-os-command-injection
            system("free -m");
            break;
        default:
            echo "Invalid action";
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_14() {
    // Using numeric validation
    $count = $_GET['count'];
    if (is_numeric($count) && $count > 0 && $count <= 10) {
        // ok: php-os-command-injection
        system("head -n $count /var/log/syslog");
    } else {
        echo "Invalid count";
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

function good_case_15() {
    // Using filter_var for validation
    $ip = $_GET['ip'];
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $safe_ip = escapeshellarg($ip);
        // ok: php-os-command-injection
        exec("ping -c 4 $safe_ip", $output);
        echo implode("\n", $output);
    } else {
        echo "Invalid IP address";
    }
}
// {/fact}
?>
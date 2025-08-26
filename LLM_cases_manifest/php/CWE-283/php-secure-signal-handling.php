<?php
// {fact rule=secure-signal-handling@v1.0 defects=1}
// PHP Secure Signal Handling Examples

// True Positives (Vulnerable Code)

function bad_case_1() {
    $pid = $_GET['process_id']; // Getting PID from user input without validation
    // ruleid: php-secure-signal-handling
    posix_kill($pid, SIGTERM); // Sending SIGTERM signal without validating PID
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_2() {
    $pid = $_POST['target_process'];
    $signal = $_POST['signal_type'];
    // ruleid: php-secure-signal-handling
    posix_kill($pid, $signal); // Both PID and signal are unvalidated user inputs
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_3() {
    $user_input = $_REQUEST['process_group'];
    // ruleid: php-secure-signal-handling
    posix_kill(-$user_input, SIGHUP); // Negative PID for process groups without validation
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_4() {
    $pids = explode(',', $_GET['process_list']);
    foreach ($pids as $pid) {
        // ruleid: php-secure-signal-handling
        posix_kill((int)$pid, SIGKILL); // Simple casting isn't sufficient validation
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_5() {
    $signal_name = $_POST['signal'];
    $pid = $_POST['pid'];
    $signal_constant = constant($signal_name); // Dangerous - allows arbitrary constant lookup
    // ruleid: php-secure-signal-handling
    posix_kill($pid, $signal_constant);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_6() {
    $pid = $_COOKIE['debug_pid'];
    if (!empty($pid)) {
        // ruleid: php-secure-signal-handling
        proc_terminate(proc_open("ls", array(), $pipes), $pid); // Using unvalidated PID from cookie
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_7() {
    $process_data = json_decode($_POST['process_data'], true);
    // ruleid: php-secure-signal-handling
    posix_kill($process_data['pid'], $process_data['signal']); // Unvalidated nested input
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_8() {
    $pid = filter_input(INPUT_GET, 'pid', FILTER_SANITIZE_NUMBER_INT); // Not enough for security
    // ruleid: php-secure-signal-handling
    posix_kill($pid, SIGINT); // FILTER_SANITIZE_* doesn't validate, only sanitizes
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_9() {
    $pid = $_SERVER['HTTP_X_PROCESS_ID']; // Getting PID from HTTP header
    // ruleid: php-secure-signal-handling
    posix_kill($pid, SIGUSR1); // Unvalidated header input
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_10() {
    $target_pid = $_GET['pid'] ?? getmypid(); // Default fallback doesn't make it secure
    // ruleid: php-secure-signal-handling
    posix_kill($target_pid, SIGTERM);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_11() {
    parse_str($_SERVER['QUERY_STRING'], $params);
    // ruleid: php-secure-signal-handling
    posix_kill($params['pid'], SIGSTOP); // Unvalidated query string parsing
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_12() {
    session_start();
    $pid = $_SESSION['stored_pid']; // Even session data should be validated
    // ruleid: php-secure-signal-handling
    posix_kill($pid, SIGCONT);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_13() {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    // ruleid: php-secure-signal-handling
    posix_kill($data['process']['id'], SIGABRT); // Raw input without validation
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_14() {
    $pid = base64_decode($_POST['encoded_pid']); // Decoding doesn't validate
    // ruleid: php-secure-signal-handling
    posix_kill($pid, SIGQUIT);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=1}

function bad_case_15() {
    $pid_list = $_GET['pids'];
    $signal = $_GET['signal'] ?: SIGTERM;
    foreach (explode(',', $pid_list) as $current_pid) {
        // ruleid: php-secure-signal-handling
        posix_kill(trim($current_pid), $signal); // Trimming isn't sufficient validation
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

// True Negatives (Secure Code)

function good_case_1() {
    $pid = $_GET['process_id'];
    if (is_numeric($pid) && $pid > 0 && posix_getpgid($pid) !== false) {
        // ok: php-secure-signal-handling
        posix_kill((int)$pid, SIGTERM); // Validated PID
    } else {
        error_log("Invalid PID provided");
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_2() {
    $pid = filter_input(INPUT_POST, 'target_process', FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1]
    ]);
    if ($pid !== false && posix_kill($pid, 0)) { // Check if process exists
        // ok: php-secure-signal-handling
        posix_kill($pid, SIGHUP);
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_3() {
    $user_input = $_REQUEST['process_group'];
    $pgid = filter_var($user_input, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1]
    ]);
    if ($pgid !== false && posix_getpgid($pgid) !== false) {
        // ok: php-secure-signal-handling
        posix_kill(-$pgid, SIGTERM); // Properly validated process group
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_4() {
    $allowed_signals = [SIGTERM, SIGKILL, SIGINT];
    $signal = $_POST['signal'] ?? SIGTERM;
    $pid = $_POST['pid'];
    
    if (is_numeric($pid) && $pid > 0 && in_array((int)$signal, $allowed_signals, true)) {
        // ok: php-secure-signal-handling
        posix_kill((int)$pid, (int)$signal);
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_5() {
    $pid = filter_input(INPUT_GET, 'pid', FILTER_VALIDATE_INT);
    if ($pid !== false && $pid > 0) {
        // Verify the process belongs to the current user
        $process_owner = posix_getpwuid(posix_geteuid());
        $stat_file = "/proc/$pid/status";
        if (file_exists($stat_file) && is_readable($stat_file)) {
            $status = file_get_contents($stat_file);
            if (strpos($status, "Uid:\t" . $process_owner['uid']) !== false) {
                // ok: php-secure-signal-handling
                posix_kill($pid, SIGTERM);
            }
        }
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_6() {
    // Using a whitelist of known, controlled PIDs
    $allowed_pids = [1234, 5678, 9012];
    $pid = $_GET['pid'];
    
    if (in_array((int)$pid, $allowed_pids, true)) {
        // ok: php-secure-signal-handling
        posix_kill((int)$pid, SIGUSR1);
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_7() {
    // Only allow signaling child processes
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"]
    ];
    $process = proc_open("sleep 10", $descriptorspec, $pipes);
    $status = proc_get_status($process);
    $child_pid = $status['pid'];
    
    // ok: php-secure-signal-handling
    posix_kill($child_pid, SIGTERM);
    proc_close($process);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_8() {
    // Using a secure configuration file instead of user input
    $config = parse_ini_file('/etc/app/processes.ini', true);
    $service_name = 'web_server';
    
    if (isset($config[$service_name]['pid']) && is_numeric($config[$service_name]['pid'])) {
        $pid = (int)$config[$service_name]['pid'];
        // ok: php-secure-signal-handling
        posix_kill($pid, SIGHUP); // Reload configuration
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_9() {
    // Only allow signaling the current process
    $current_pid = getmypid();
    // ok: php-secure-signal-handling
    posix_kill($current_pid, SIGUSR1);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_10() {
    $pid = $_POST['pid'];
    // Comprehensive validation
    if (!is_numeric($pid) || $pid <= 0 || $pid >= 100000) {
        die("Invalid PID");
    }
    
    // Check if we have permission to signal this process
    if (posix_kill($pid, 0)) {
        // ok: php-secure-signal-handling
        posix_kill($pid, SIGTERM);
    } else {
        error_log("No permission to signal process $pid");
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_11() {
    // Using a database to store authorized PIDs
    $db = new PDO('mysql:host=localhost;dbname=app', 'user', 'password');
    $stmt = $db->prepare("SELECT pid FROM authorized_processes WHERE service = ?");
    $stmt->execute([$_GET['service']]);
    $pid = $stmt->fetchColumn();
    
    if ($pid && is_numeric($pid) && $pid > 0) {
        // ok: php-secure-signal-handling
        posix_kill((int)$pid, SIGHUP);
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_12() {
    // Using a secure hash to verify the PID hasn't been tampered with
    $pid = $_GET['pid'];
    $hash = $_GET['hash'];
    $secret = 'your-secret-key';
    
    if (is_numeric($pid) && $pid > 0 && hash_equals(hash_hmac('sha256', $pid, $secret), $hash)) {
        // ok: php-secure-signal-handling
        posix_kill((int)$pid, SIGTERM);
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_13() {
    // Using environment variables instead of user input
    $pid_file = getenv('PID_FILE');
    if ($pid_file && file_exists($pid_file)) {
        $pid = trim(file_get_contents($pid_file));
        if (is_numeric($pid) && $pid > 0) {
            // ok: php-secure-signal-handling
            posix_kill((int)$pid, SIGTERM);
        }
    }
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_14() {
    // Using a secure API for process management
    class ProcessManager {
        private $authorized_pids = [];
        
        public function __construct() {
            // Initialize with known safe PIDs
            $this->authorized_pids = [1234, 5678];
        }
        
        public function signalProcess($pid, $signal) {
            if (in_array($pid, $this->authorized_pids, true)) {
                // ok: php-secure-signal-handling
                return posix_kill($pid, $signal);
            }
            return false;
        }
    }
    
    $manager = new ProcessManager();
    $manager->signalProcess(1234, SIGTERM);
}
// {/fact}
// {fact rule=secure-signal-handling@v1.0 defects=0}

function good_case_15() {
    // Using a secure configuration system
    $config_dir = '/etc/app/processes/';
    $service = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['service']); // Sanitize service name
    
    if (empty($service) || !file_exists($config_dir . $service . '.pid')) {
        die("Invalid service");
    }
    
    $pid = (int)trim(file_get_contents($config_dir . $service . '.pid'));
    if ($pid > 0) {
        // ok: php-secure-signal-handling
        posix_kill($pid, SIGHUP);
    }
}
// {/fact}
?>
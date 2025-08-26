<?php
// {fact rule=insecure-cookie@v1.0 defects=1}
// Test cases for php-ftp-use rule (CWE-319)
// This rule detects insecure use of FTP protocol which lacks encryption

// TRUE POSITIVES (Vulnerable code that should be detected)

function bad_case_1() {
    // Basic FTP connection
    $conn = ftp_connect('ftp.example.com');
    // ruleid: php-ftp-use
    $login = ftp_login($conn, 'username', 'password');
    
    if ($login) {
        ftp_get($conn, 'local_file.txt', 'remote_file.txt', FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_2() {
    // FTP connection with port specification
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.example.com', 21);
    $login = ftp_login($conn, 'username', 'password');
    
    // Upload a file
    if ($login) {
        $file = 'sensitive_data.csv';
        ftp_put($conn, 'remote_' . $file, $file, FTP_ASCII);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_3() {
    // FTP connection with timeout
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.example.com', 21, 30);
    $login = ftp_login($conn, 'username', 'password');
    
    if ($login) {
        // List directory contents
        $contents = ftp_nlist($conn, '.');
        print_r($contents);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_4() {
    // FTP with passive mode
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.company.internal');
    $login = ftp_login($conn, 'admin', 'secure_password');
    
    if ($login) {
        ftp_pasv($conn, true);
        ftp_get($conn, 'local_backup.sql', 'database_backup.sql', FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_5() {
    // FTP in a loop for multiple files
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.dataserver.com');
    $login = ftp_login($conn, 'user123', 'pass456');
    
    if ($login) {
        $files = ['report1.pdf', 'report2.pdf', 'report3.pdf'];
        foreach ($files as $file) {
            ftp_get($conn, 'downloads/' . $file, $file, FTP_BINARY);
        }
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_6() {
    // FTP with dynamic server from config
    $config = [
        'server' => 'ftp.backups.net',
        'username' => 'backup_user',
        'password' => 'backup_pass'
    ];
    
    // ruleid: php-ftp-use
    $conn = ftp_connect($config['server']);
    $login = ftp_login($conn, $config['username'], $config['password']);
    
    if ($login) {
        ftp_chdir($conn, 'daily_backups');
        ftp_put($conn, date('Y-m-d') . '_backup.zip', 'site_backup.zip', FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_7() {
    // FTP with error handling
    try {
        // ruleid: php-ftp-use
        $conn = ftp_connect('ftp.storage.example.org');
        if (!$conn) {
            throw new Exception('Could not connect to FTP server');
        }
        
        $login = ftp_login($conn, 'ftpuser', 'ftppass');
        if (!$login) {
            throw new Exception('Could not login to FTP server');
        }
        
        $upload = ftp_put($conn, 'customer_data.csv', 'exports/customers.csv', FTP_ASCII);
        if (!$upload) {
            throw new Exception('Could not upload file');
        }
        
        ftp_close($conn);
    } catch (Exception $e) {
        error_log('FTP Error: ' . $e->getMessage());
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_8() {
    // FTP with directory creation and navigation
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.filestore.com');
    $login = ftp_login($conn, 'admin', 'complex_pwd!');
    
    if ($login) {
        // Create directory if it doesn't exist
        if (!@ftp_chdir($conn, 'uploads')) {
            ftp_mkdir($conn, 'uploads');
            ftp_chdir($conn, 'uploads');
        }
        
        // Create subdirectory for today's date
        $today = date('Y-m-d');
        if (!@ftp_chdir($conn, $today)) {
            ftp_mkdir($conn, $today);
            ftp_chdir($conn, $today);
        }
        
        ftp_put($conn, 'log.txt', 'system_log.txt', FTP_ASCII);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_9() {
    // FTP in a class method
    class FileUploader {
        private $conn;
        
        public function uploadFile($localFile, $remoteFile) {
            // ruleid: php-ftp-use
            $this->conn = ftp_connect('ftp.uploads.net');
            $login = ftp_login($this->conn, 'uploader', 'upload123');
            
            if ($login) {
                ftp_put($this->conn, $remoteFile, $localFile, FTP_BINARY);
            }
            
            ftp_close($this->conn);
        }
    }
    
    $uploader = new FileUploader();
    $uploader->uploadFile('local_image.jpg', 'profile_pic.jpg');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_10() {
    // FTP with connection from user input
    $server = $_POST['ftp_server'] ?? 'default-ftp.example.com';
    $username = $_POST['username'] ?? 'default_user';
    $password = $_POST['password'] ?? 'default_pass';
    
    // ruleid: php-ftp-use
    $conn = ftp_connect($server);
    $login = ftp_login($conn, $username, $password);
    
    if ($login) {
        $file = $_FILES['upload']['tmp_name'];
        $remote_file = $_FILES['upload']['name'];
        ftp_put($conn, $remote_file, $file, FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_11() {
    // FTP with conditional connection based on configuration
    $config = [
        'use_secure' => false,
        'server' => 'ftp.documents.com',
        'username' => 'docuser',
        'password' => 'docpass'
    ];
    
    if ($config['use_secure']) {
        // This would be secure, but the config says not to use it
        $conn = null; // Would use SFTP here
    } else {
        // ruleid: php-ftp-use
        $conn = ftp_connect($config['server']);
        $login = ftp_login($conn, $config['username'], $config['password']);
        
        if ($login) {
            ftp_get($conn, 'local_document.docx', 'important_document.docx', FTP_BINARY);
        }
        
        ftp_close($conn);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_12() {
    // FTP with file permission changes
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.webhosting.com');
    $login = ftp_login($conn, 'webadmin', 'hosting_pwd');
    
    if ($login) {
        // Upload a PHP script and set permissions
        ftp_put($conn, 'update_script.php', 'local_update.php', FTP_ASCII);
        ftp_chmod($conn, 0755, 'update_script.php');
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_13() {
    // FTP with multiple operations
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.mediaserver.com');
    $login = ftp_login($conn, 'mediauser', 'media_pwd');
    
    if ($login) {
        // Set passive mode
        ftp_pasv($conn, true);
        
        // Get current directory
        $current_dir = ftp_pwd($conn);
        
        // Create new directory
        ftp_mkdir($conn, 'new_uploads');
        
        // Change to new directory
        ftp_chdir($conn, 'new_uploads');
        
        // Upload file
        ftp_put($conn, 'video.mp4', 'local_video.mp4', FTP_BINARY);
        
        // Return to original directory
        ftp_chdir($conn, $current_dir);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_14() {
    // FTP with raw commands
    // ruleid: php-ftp-use
    $conn = ftp_connect('ftp.legacy-system.org');
    $login = ftp_login($conn, 'legacy', 'old_pwd');
    
    if ($login) {
        // Send raw FTP command
        ftp_raw($conn, 'SITE CHMOD 644 config.ini');
        
        // Get a file
        ftp_get($conn, 'local_config.ini', 'config.ini', FTP_ASCII);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_15() {
    // FTP connection in a function that returns the connection
    function getFtpConnection() {
        // ruleid: php-ftp-use
        $conn = ftp_connect('ftp.internal-server.com');
        $login = ftp_login($conn, 'internal', 'int_pwd');
        
        if (!$login) {
            return false;
        }
        
        return $conn;
    }
    
    $conn = getFtpConnection();
    if ($conn) {
        ftp_get($conn, 'local_data.xml', 'export.xml', FTP_ASCII);
        ftp_close($conn);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// TRUE NEGATIVES (Secure code that should not be detected)

function good_case_1() {
    // Using SFTP instead of FTP
    // ok: php-ftp-use
    $sftp = ssh2_connect('sftp.example.com', 22);
    ssh2_auth_password($sftp, 'username', 'password');
    $sftp_stream = ssh2_sftp($sftp);
    
    // Copy file via SFTP
    $stream = fopen("ssh2.sftp://$sftp_stream/remote_file.txt", 'r');
    $contents = fread($stream, filesize('remote_file.txt'));
    fclose($stream);
    
    file_put_contents('local_file.txt', $contents);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_2() {
    // Using FTPS (FTP over SSL) with explicit encryption
    // ok: php-ftp-use
    $conn = ftp_ssl_connect('ftps.example.com');
    $login = ftp_login($conn, 'username', 'password');
    
    if ($login) {
        ftp_get($conn, 'local_file.txt', 'remote_file.txt', FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_3() {
    // Using SFTP with key-based authentication
    // ok: php-ftp-use
    $connection = ssh2_connect('sftp.company.com', 22);
    ssh2_auth_pubkey_file(
        $connection,
        'username',
        '/path/to/public_key.pub',
        '/path/to/private_key',
        'passphrase'
    );
    
    $sftp = ssh2_sftp($connection);
    $stream = fopen("ssh2.sftp://$sftp/path/to/remote_file.txt", 'w');
    fwrite($stream, 'File content goes here');
    fclose($stream);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_4() {
    // Using FTPS with passive mode
    // ok: php-ftp-use
    $conn = ftp_ssl_connect('ftps.secure-server.com');
    $login = ftp_login($conn, 'secure_user', 'secure_pass');
    
    if ($login) {
        ftp_pasv($conn, true);
        ftp_put($conn, 'remote_backup.sql', 'local_backup.sql', FTP_BINARY);
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_5() {
    // Using SFTP with error handling
    try {
        // ok: php-ftp-use
        $connection = ssh2_connect('sftp.dataserver.com', 22);
        if (!$connection) {
            throw new Exception('Could not connect to SFTP server');
        }
        
        $auth = ssh2_auth_password($connection, 'user123', 'pass456');
        if (!$auth) {
            throw new Exception('Authentication failed');
        }
        
        $sftp = ssh2_sftp($connection);
        $files = ['report1.pdf', 'report2.pdf', 'report3.pdf'];
        
        foreach ($files as $file) {
            $remote_file = "ssh2.sftp://$sftp/$file";
            $local_file = "downloads/$file";
            
            if (!copy($remote_file, $local_file)) {
                throw new Exception("Could not download $file");
            }
        }
    } catch (Exception $e) {
        error_log('SFTP Error: ' . $e->getMessage());
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_6() {
    // Using phpseclib for SFTP
    // ok: php-ftp-use
    require_once 'vendor/autoload.php';
    
    $sftp = new \phpseclib3\Net\SFTP('sftp.example.org');
    if (!$sftp->login('username', 'password')) {
        die('Login Failed');
    }
    
    // Upload a file
    $sftp->put('remote_file.txt', file_get_contents('local_file.txt'));
    
    // Download a file
    $sftp->get('remote_data.csv', 'local_data.csv');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_7() {
    // Using HTTP/HTTPS for file transfer
    // ok: php-ftp-use
    $file_url = 'https://secure.example.com/files/document.pdf';
    $local_file = 'downloaded_document.pdf';
    
    $options = [
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ];
    
    $context = stream_context_create($options);
    $file_content = file_get_contents($file_url, false, $context);
    
    if ($file_content !== false) {
        file_put_contents($local_file, $file_content);
        echo "File downloaded successfully.";
    } else {
        echo "Failed to download file.";
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_8() {
    // Using FTPS in a class
    class SecureFileTransfer {
        private $conn;
        
        public function uploadFile($localFile, $remoteFile) {
            // ok: php-ftp-use
            $this->conn = ftp_ssl_connect('ftps.secure-uploads.net');
            $login = ftp_login($this->conn, 'secure_user', 'secure_pass');
            
            if ($login) {
                ftp_pasv($this->conn, true);
                ftp_put($this->conn, $remoteFile, $localFile, FTP_BINARY);
            }
            
            ftp_close($this->conn);
        }
    }
    
    $transfer = new SecureFileTransfer();
    $transfer->uploadFile('local_image.jpg', 'profile_pic.jpg');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_9() {
    // Using SFTP with phpseclib and directory operations
    // ok: php-ftp-use
    require_once 'vendor/autoload.php';
    
    $sftp = new \phpseclib3\Net\SFTP('sftp.filestore.com');
    if (!$sftp->login('admin', 'complex_pwd!')) {
        die('Login Failed');
    }
    
    // Create directory if it doesn't exist
    if (!$sftp->is_dir('uploads')) {
        $sftp->mkdir('uploads');
    }
    $sftp->chdir('uploads');
    
    // Create subdirectory for today's date
    $today = date('Y-m-d');
    if (!$sftp->is_dir($today)) {
        $sftp->mkdir($today);
    }
    $sftp->chdir($today);
    
    // Upload file
    $sftp->put('log.txt', file_get_contents('system_log.txt'));
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_10() {
    // Using CURL with SFTP
    // ok: php-ftp-use
    $ch = curl_init();
    
    curl_setopt($ch, CURLOPT_URL, 'sftp://sftp.example.com/path/to/remote_file.txt');
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_SFTP);
    curl_setopt($ch, CURLOPT_USERPWD, 'username:password');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    
    $file_content = curl_exec($ch);
    
    if (curl_errno($ch)) {
        echo 'Error: ' . curl_error($ch);
    } else {
        file_put_contents('local_file.txt', $file_content);
    }
    
    curl_close($ch);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_11() {
    // Using AWS S3 for file storage instead of FTP
    // ok: php-ftp-use
    require 'vendor/autoload.php';
    
    $s3 = new \Aws\S3\S3Client([
        'version' => 'latest',
        'region'  => 'us-west-2',
        'credentials' => [
            'key'    => getenv('AWS_ACCESS_KEY_ID'),
            'secret' => getenv('AWS_SECRET_ACCESS_KEY'),
        ],
    ]);
    
    // Upload a file
    $s3->putObject([
        'Bucket' => 'my-bucket',
        'Key'    => 'remote_filename.txt',
        'Body'   => fopen('local_file.txt', 'r'),
        'ACL'    => 'private',
    ]);
    
    // Download a file
    $result = $s3->getObject([
        'Bucket' => 'my-bucket',
        'Key'    => 'remote_data.csv',
    ]);
    
    file_put_contents('downloaded_data.csv', $result['Body']);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_12() {
    // Using FTPS with explicit configuration
    // ok: php-ftp-use
    $conn = ftp_ssl_connect('ftps.webhosting.com');
    $login = ftp_login($conn, 'webadmin', 'hosting_pwd');
    
    if ($login) {
        // Set required SSL session options
        ftp_exec($conn, 'PBSZ 0');
        ftp_exec($conn, 'PROT P');
        
        // Upload a PHP script and set permissions
        ftp_put($conn, 'update_script.php', 'local_update.php', FTP_ASCII);
        ftp_chmod($conn, 0755, 'update_script.php');
    }
    
    ftp_close($conn);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_13() {
    // Using SFTP with session management
    // ok: php-ftp-use
    require_once 'vendor/autoload.php';
    
    $sftp = new \phpseclib3\Net\SFTP('sftp.mediaserver.com');
    if (!$sftp->login('mediauser', 'media_pwd')) {
        die('Login Failed');
    }
    
    // Get current directory
    $current_dir = $sftp->pwd();
    
    // Create new directory
    $sftp->mkdir('new_uploads');
    
    // Change to new directory
    $sftp->chdir('new_uploads');
    
    // Upload file
    $sftp->put('video.mp4', file_get_contents('local_video.mp4'));
    
    // Return to original directory
    $sftp->chdir($current_dir);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_14() {
    // Using SCP for file transfer
    // ok: php-ftp-use
    $connection = ssh2_connect('secure.example.org', 22);
    ssh2_auth_password($connection, 'username', 'password');
    
    // Copy file from local to remote server using SCP
    ssh2_scp_send($connection, 'local_file.txt', 'remote_file.txt', 0644);
    
    // Copy file from remote to local server using SCP
    ssh2_scp_recv($connection, 'remote_config.ini', 'local_config.ini');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_15() {
    // Using SFTP with configuration from environment variables
    // ok: php-ftp-use
    require_once 'vendor/autoload.php';
    
    $host = getenv('SFTP_HOST') ?: 'default-sftp.example.com';
    $username = getenv('SFTP_USERNAME') ?: 'default_user';
    $password = getenv('SFTP_PASSWORD') ?: 'default_pass';
    
    $sftp = new \phpseclib3\Net\SFTP($host);
    if (!$sftp->login($username, $password)) {
        die('Login Failed');
    }
    
    // Upload file
    if (isset($_FILES['upload'])) {
        $local_file = $_FILES['upload']['tmp_name'];
        $remote_file = $_FILES['upload']['name'];
        $sftp->put($remote_file, file_get_contents($local_file));
    }
}
// {/fact}
?>
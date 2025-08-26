<?php

// This file contains test cases for the php-phpmailer-smtp-insecure rule
// which detects SMTP connections without SSL/TLS encryption

require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;
// {fact rule=insecure-cookie@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    $mail = new PHPMailer(true);
    
    // Server settings
    $mail->isSMTP();
    $mail->Host = 'smtp.example.com';
    // ruleid: php-phpmailer-smtp-insecure
    $mail->SMTPAuth = true;
    $mail->Username = 'user@example.com';
    $mail->Password = 'password123';
    
    // No SMTPSecure setting, defaults to insecure connection
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_2() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.company.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'user@company.com';
    $mail->Password = 'secret';
    $mail->Port = 25; // Default insecure port
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_3() {
    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mailer->Host = 'mail.organization.org';
    $mailer->SMTPAuth = true;
    $mailer->Username = $_ENV['MAIL_USERNAME'];
    $mailer->Password = $_ENV['MAIL_PASSWORD'];
    // Explicitly setting SMTPSecure to empty string
    $mailer->SMTPSecure = '';
    
    $mailer->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_4() {
    $mail = new PHPMailer();
    
    // Server settings with explicit insecure configuration
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.domain.net';
    $mail->SMTPAuth = true;
    $mail->Username = 'admin@domain.net';
    $mail->Password = 'admin123';
    $mail->SMTPSecure = false; // Explicitly disabled security
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_5() {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        // ruleid: php-phpmailer-smtp-insecure
        $mail->Host = 'smtp-server.local';
        $mail->SMTPAuth = true;
        $mail->Username = 'local-user';
        $mail->Password = 'local-pass';
        $mail->Port = 587; // Even though this is typically TLS port, no SMTPSecure is set
        
        $mail->send();
    } catch (Exception $e) {
        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_6() {
    $config = [
        'host' => 'mail.example.org',
        'username' => 'system@example.org',
        'password' => 'sys123',
        'port' => 25
    ];
    
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = $config['host'];
    $mail->SMTPAuth = true;
    $mail->Username = $config['username'];
    $mail->Password = $config['password'];
    $mail->Port = $config['port'];
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_7() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    
    if (isset($_POST['use_encryption']) && $_POST['use_encryption'] === 'yes') {
        $mail->SMTPSecure = 'tls';
    } else {
        // ruleid: php-phpmailer-smtp-insecure
        $mail->Host = 'smtp.mailserver.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'user';
        $mail->Password = 'pass';
        // No encryption set in this branch
    }
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_8() {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.corporate-mail.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'corporate-user';
    $mail->Password = 'corporate-pass';
    
    // SMTPSecure is commented out
    // $mail->SMTPSecure = 'tls';
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_9() {
    $options = [
        'encryption' => null, // No encryption
        'host' => 'smtp.internal-network.com',
        'auth' => true,
        'username' => 'internal-user',
        'password' => 'internal-pass'
    ];
    
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = $options['host'];
    $mail->SMTPAuth = $options['auth'];
    $mail->Username = $options['username'];
    $mail->Password = $options['password'];
    
    if ($options['encryption']) {
        $mail->SMTPSecure = $options['encryption'];
    }
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_10() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'relay.example.com';
    $mail->SMTPAuth = false; // No authentication, but still insecure
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_11() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'localhost'; // Local SMTP server
    $mail->SMTPAuth = true;
    $mail->Username = 'local-admin';
    $mail->Password = 'local-admin-pass';
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_12() {
    $mail = new PHPMailer(true);
    
    // Complex configuration with multiple hosts but no encryption
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp1.example.com;smtp2.example.com'; // Multiple hosts
    $mail->SMTPAuth = true;
    $mail->Username = 'backup-user';
    $mail->Password = 'backup-pass';
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_13() {
    $mail = new PHPMailer();
    
    // Dynamic configuration from database
    $db_config = [
        'host' => 'smtp.service.net',
        'auth' => true,
        'username' => 'service-user',
        'password' => 'service-pass',
        'encryption' => '' // Empty string means no encryption
    ];
    
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = $db_config['host'];
    $mail->SMTPAuth = $db_config['auth'];
    $mail->Username = $db_config['username'];
    $mail->Password = $db_config['password'];
    $mail->SMTPSecure = $db_config['encryption']; // Empty string
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_14() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    
    // Using string concatenation for host
    $domain = 'example.net';
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.' . $domain;
    $mail->SMTPAuth = true;
    $mail->Username = 'user@' . $domain;
    $mail->Password = 'domain-pass';
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_15() {
    $mail = new PHPMailer();
    
    // Using a function to get host
    function getMailServer() {
        return 'mail.company-internal.com';
    }
    
    $mail->isSMTP();
    // ruleid: php-phpmailer-smtp-insecure
    $mail->Host = getMailServer();
    $mail->SMTPAuth = true;
    $mail->Username = 'internal-mailer';
    $mail->Password = 'int-mail-pass';
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

function good_case_1() {
    $mail = new PHPMailer(true);
    
    // Server settings with TLS
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.example.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'user@example.com';
    $mail->Password = 'password123';
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_2() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.company.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'user@company.com';
    $mail->Password = 'secret';
    $mail->SMTPSecure = 'ssl';
    $mail->Port = 465;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_3() {
    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mailer->Host = 'ssl://mail.organization.org';
    $mailer->SMTPAuth = true;
    $mailer->Username = $_ENV['MAIL_USERNAME'];
    $mailer->Password = $_ENV['MAIL_PASSWORD'];
    $mailer->Port = 465;
    
    $mailer->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_4() {
    $mail = new PHPMailer();
    
    // Server settings with explicit secure configuration
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'tls://smtp.domain.net';
    $mail->SMTPAuth = true;
    $mail->Username = 'admin@domain.net';
    $mail->Password = 'admin123';
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_5() {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        // ok: php-phpmailer-smtp-insecure
        $mail->Host = 'smtp-server.local';
        $mail->SMTPAuth = true;
        $mail->Username = 'local-user';
        $mail->Password = 'local-pass';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;
        
        $mail->send();
    } catch (Exception $e) {
        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_6() {
    $config = [
        'host' => 'mail.example.org',
        'username' => 'system@example.org',
        'password' => 'sys123',
        'port' => 465,
        'encryption' => 'ssl'
    ];
    
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = $config['host'];
    $mail->SMTPAuth = true;
    $mail->Username = $config['username'];
    $mail->Password = $config['password'];
    $mail->SMTPSecure = $config['encryption'];
    $mail->Port = $config['port'];
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_7() {
    $mail = new PHPMailer();
    $mail->isSMTP();
    
    // Dynamic configuration with encryption
    $encryption_type = 'tls';
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.mailserver.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'user';
    $mail->Password = 'pass';
    $mail->SMTPSecure = $encryption_type;
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_8() {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.corporate-mail.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'corporate-user';
    $mail->Password = 'corporate-pass';
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->Port = 465;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_9() {
    $options = [
        'encryption' => 'ssl',
        'host' => 'smtp.internal-network.com',
        'auth' => true,
        'username' => 'internal-user',
        'password' => 'internal-pass',
        'port' => 465
    ];
    
    $mail = new PHPMailer();
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = $options['host'];
    $mail->SMTPAuth = $options['auth'];
    $mail->Username = $options['username'];
    $mail->Password = $options['password'];
    $mail->SMTPSecure = $options['encryption'];
    $mail->Port = $options['port'];
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_10() {
    $mail = new PHPMailer();
    
    // Using environment variables for configuration
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = $_ENV['SMTP_HOST'];
    $mail->SMTPAuth = true;
    $mail->Username = $_ENV['SMTP_USER'];
    $mail->Password = $_ENV['SMTP_PASS'];
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_11() {
    $mail = new PHPMailer();
    
    // Conditional encryption based on environment
    $is_production = true;
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.service.net';
    $mail->SMTPAuth = true;
    $mail->Username = 'service-user';
    $mail->Password = 'service-pass';
    
    if ($is_production) {
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;
    } else {
        $mail->SMTPSecure = 'ssl';
        $mail->Port = 465;
    }
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_12() {
    $mail = new PHPMailer();
    
    // Using string concatenation for host with SSL prefix
    $domain = 'example.net';
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'ssl://smtp.' . $domain;
    $mail->isSMTP();
    $mail->SMTPAuth = true;
    $mail->Username = 'user@' . $domain;
    $mail->Password = 'domain-pass';
    $mail->Port = 465;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_13() {
    $mail = new PHPMailer();
    
    // Using a function to get secure host
    function getSecureMailServer() {
        return 'tls://mail.company-internal.com';
    }
    
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = getSecureMailServer();
    $mail->SMTPAuth = true;
    $mail->Username = 'internal-mailer';
    $mail->Password = 'int-mail-pass';
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_14() {
    $mail = new PHPMailer();
    
    // Multiple hosts with TLS
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp1.example.com;smtp2.example.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'backup-user';
    $mail->Password = 'backup-pass';
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;
    
    $mail->send();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_15() {
    $mail = new PHPMailer();
    
    // Using constants for encryption
    define('MAIL_ENCRYPTION', 'ssl');
    
    $mail->isSMTP();
    // ok: php-phpmailer-smtp-insecure
    $mail->Host = 'smtp.secure-provider.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'secure-user';
    $mail->Password = 'secure-pass';
    $mail->SMTPSecure = MAIL_ENCRYPTION;
    $mail->Port = 465;
    
    $mail->send();
}
// {/fact}
?>
<?php
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positives (Vulnerable Code)

function bad_case_1() {
    $ldapconn = ldap_connect("ldap.example.com");
    
    // ruleid: php-ldap-bind-without-password
    ldap_bind($ldapconn); // Anonymous bind - no username or password
    
    $search = ldap_search($ldapconn, "dc=example,dc=com", "(objectClass=*)");
    $entries = ldap_get_entries($ldapconn, $search);
    
    ldap_close($ldapconn);
    return $entries;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_2() {
    $ldap_host = "ldap.example.com";
    $ldap_conn = ldap_connect($ldap_host);
    ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // ruleid: php-ldap-bind-without-password
    if (ldap_bind($ldap_conn)) {
        echo "LDAP bind successful";
        $search_result = ldap_search($ldap_conn, "dc=example,dc=com", "(uid=*)");
        $data = ldap_get_entries($ldap_conn, $search_result);
    }
    ldap_close($ldap_conn);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_3() {
    $ldapserver = 'ldap://directory.example.com';
    $ldapport = 389;
    
    $ds = ldap_connect($ldapserver, $ldapport);
    ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
    
    // ruleid: php-ldap-bind-without-password
    $bind = ldap_bind($ds);
    
    if ($bind) {
        $filter = "(objectClass=person)";
        $result = ldap_search($ds, "ou=users,dc=example,dc=com", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_4() {
    $username = $_POST['username'];
    $ldap = ldap_connect("ldap.example.com");
    
    // ruleid: php-ldap-bind-without-password
    $bind = @ldap_bind($ldap);
    
    if ($bind) {
        $filter = "(uid=$username)";
        $result = ldap_search($ldap, "dc=example,dc=com", $filter);
        $info = ldap_get_entries($ldap, $result);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_5() {
    $ldapconn = ldap_connect("ldap://ad.example.com");
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    try {
        // ruleid: php-ldap-bind-without-password
        if (ldap_bind($ldapconn)) {
            $filter = "(sAMAccountName=*)";
            $result = ldap_search($ldapconn, "dc=ad,dc=example,dc=com", $filter);
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_6() {
    $ldap = ldap_connect("ldaps://ldap.example.org");
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // ruleid: php-ldap-bind-without-password
    $anonymous_bind = ldap_bind($ldap);
    
    if ($anonymous_bind) {
        $baseDN = "ou=public,dc=example,dc=org";
        $filter = "(objectClass=*)";
        $attributes = array("cn", "mail");
        $result = ldap_search($ldap, $baseDN, $filter, $attributes);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_7() {
    $ldap_server = $_ENV['LDAP_SERVER'];
    $ldap = ldap_connect($ldap_server);
    
    if (!$ldap) {
        die("Could not connect to LDAP server");
    }
    
    // ruleid: php-ldap-bind-without-password
    $result = ldap_bind($ldap);
    
    if ($result) {
        $search = ldap_search($ldap, "dc=company,dc=com", "(objectClass=person)");
        $entries = ldap_get_entries($ldap, $search);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_8() {
    $ldap_host = "ldap.internal.net";
    $ldap_port = 389;
    
    $connection = ldap_connect($ldap_host, $ldap_port);
    ldap_set_option($connection, LDAP_OPT_NETWORK_TIMEOUT, 10);
    
    // ruleid: php-ldap-bind-without-password
    if (ldap_bind($connection)) {
        $base_dn = "ou=groups,dc=internal,dc=net";
        $filter = "(cn=*)";
        $search = ldap_search($connection, $base_dn, $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_9() {
    $ldapconfig['host'] = 'ldap.example.com';
    $ldapconfig['port'] = 389;
    $ds = ldap_connect($ldapconfig['host'], $ldapconfig['port']);
    
    // ruleid: php-ldap-bind-without-password
    $anonymous_bind = @ldap_bind($ds);
    
    if ($anonymous_bind) {
        $searchFilter = "(objectClass=user)";
        $baseDN = "dc=example,dc=com";
        $result = ldap_search($ds, $baseDN, $searchFilter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_10() {
    $ldap = ldap_connect("ldap://directory.example.org");
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
    
    // ruleid: php-ldap-bind-without-password
    $bind_result = ldap_bind($ldap);
    
    if ($bind_result) {
        $search_filter = "(mail=*)";
        $base_dn = "ou=people,dc=example,dc=org";
        $search_result = ldap_search($ldap, $base_dn, $search_filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_11() {
    $server = "ldap.company.local";
    $connection = ldap_connect($server);
    
    if ($connection) {
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        // ruleid: php-ldap-bind-without-password
        $bind = ldap_bind($connection);
        
        if ($bind) {
            $search_base = "ou=departments,dc=company,dc=local";
            $search_filter = "(department=*)";
            $result = ldap_search($connection, $search_base, $search_filter);
        }
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_12() {
    $ldap_server = "ldap://auth.example.net";
    $ds = ldap_connect($ldap_server);
    
    if (!$ds) {
        echo "Unable to connect to LDAP server";
        exit;
    }
    
    // ruleid: php-ldap-bind-without-password
    $bind = ldap_bind($ds);
    
    if ($bind) {
        $user_id = $_GET['user'];
        $filter = "(uid=$user_id)";
        $result = ldap_search($ds, "ou=users,dc=example,dc=net", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_13() {
    $ldap_uri = "ldap://directory.example.com:389";
    $ldap = ldap_connect($ldap_uri);
    
    if ($ldap) {
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        // ruleid: php-ldap-bind-without-password
        $is_bound = ldap_bind($ldap);
        
        if ($is_bound) {
            $base_dn = "dc=example,dc=com";
            $filter = "(objectClass=posixAccount)";
            $search = ldap_search($ldap, $base_dn, $filter);
        }
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_14() {
    $ldap_connection = ldap_connect("ldap://ldap.example.org");
    
    if (!$ldap_connection) {
        die("Could not connect to LDAP server");
    }
    
    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // ruleid: php-ldap-bind-without-password
    $anonymous_bind = ldap_bind($ldap_connection);
    
    if ($anonymous_bind) {
        $email = $_POST['email'];
        $filter = "(mail=$email)";
        $result = ldap_search($ldap_connection, "ou=staff,dc=example,dc=org", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_15() {
    $ldap_host = "ldap.internal.example.com";
    $ldap = ldap_connect($ldap_host);
    
    if ($ldap === false) {
        return false;
    }
    
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, 5);
    
    // ruleid: php-ldap-bind-without-password
    $bind_result = @ldap_bind($ldap);
    
    if ($bind_result) {
        $base_dn = "ou=public,dc=internal,dc=example,dc=com";
        $search = ldap_search($ldap, $base_dn, "(objectClass=*)");
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negatives (Secure Code)

function good_case_1() {
    $ldapconn = ldap_connect("ldap.example.com");
    $ldaprdn = 'cn=admin,dc=example,dc=com';
    $ldappass = 'secure_password';
    
    // ok: php-ldap-bind-without-password
    ldap_bind($ldapconn, $ldaprdn, $ldappass); // Authenticated bind with username and password
    
    $search = ldap_search($ldapconn, "dc=example,dc=com", "(objectClass=*)");
    $entries = ldap_get_entries($ldapconn, $search);
    
    ldap_close($ldapconn);
    return $entries;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_2() {
    $ldap_host = "ldap.example.com";
    $ldap_conn = ldap_connect($ldap_host);
    ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    $username = "cn=directory_user,dc=example,dc=com";
    $password = $_ENV['LDAP_PASSWORD'];
    
    // ok: php-ldap-bind-without-password
    if (ldap_bind($ldap_conn, $username, $password)) {
        echo "LDAP bind successful";
        $search_result = ldap_search($ldap_conn, "dc=example,dc=com", "(uid=*)");
        $data = ldap_get_entries($ldap_conn, $search_result);
    }
    ldap_close($ldap_conn);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_3() {
    $ldapserver = 'ldap://directory.example.com';
    $ldapport = 389;
    
    $ds = ldap_connect($ldapserver, $ldapport);
    ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
    
    $ldapuser = 'cn=reader,dc=example,dc=com';
    $ldappassword = getenv('LDAP_READER_PASSWORD');
    
    // ok: php-ldap-bind-without-password
    $bind = ldap_bind($ds, $ldapuser, $ldappassword);
    
    if ($bind) {
        $filter = "(objectClass=person)";
        $result = ldap_search($ds, "ou=users,dc=example,dc=com", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_4() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $ldap = ldap_connect("ldap.example.com");
    
    // ok: php-ldap-bind-without-password
    $bind = @ldap_bind($ldap, "uid=$username,ou=users,dc=example,dc=com", $password);
    
    if ($bind) {
        $filter = "(uid=$username)";
        $result = ldap_search($ldap, "dc=example,dc=com", $filter);
        $info = ldap_get_entries($ldap, $result);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_5() {
    $ldapconn = ldap_connect("ldap://ad.example.com");
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    $username = "domain\\user";
    $password = file_get_contents('/secure/ldap_password.txt');
    
    try {
        // ok: php-ldap-bind-without-password
        if (ldap_bind($ldapconn, $username, $password)) {
            $filter = "(sAMAccountName=*)";
            $result = ldap_search($ldapconn, "dc=ad,dc=example,dc=com", $filter);
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_6() {
    $ldap = ldap_connect("ldaps://ldap.example.org");
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    $bindDN = "cn=readonly,dc=example,dc=org";
    $bindPassword = $_ENV['LDAP_PASSWORD'];
    
    // ok: php-ldap-bind-without-password
    $bind = ldap_bind($ldap, $bindDN, $bindPassword);
    
    if ($bind) {
        $baseDN = "ou=users,dc=example,dc=org";
        $filter = "(objectClass=*)";
        $attributes = array("cn", "mail");
        $result = ldap_search($ldap, $baseDN, $filter, $attributes);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_7() {
    $ldap_server = $_ENV['LDAP_SERVER'];
    $ldap = ldap_connect($ldap_server);
    
    if (!$ldap) {
        die("Could not connect to LDAP server");
    }
    
    $bind_dn = $_ENV['LDAP_BIND_DN'];
    $bind_password = $_ENV['LDAP_BIND_PASSWORD'];
    
    // ok: php-ldap-bind-without-password
    $result = ldap_bind($ldap, $bind_dn, $bind_password);
    
    if ($result) {
        $search = ldap_search($ldap, "dc=company,dc=com", "(objectClass=person)");
        $entries = ldap_get_entries($ldap, $search);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_8() {
    $ldap_host = "ldap.internal.net";
    $ldap_port = 389;
    
    $connection = ldap_connect($ldap_host, $ldap_port);
    ldap_set_option($connection, LDAP_OPT_NETWORK_TIMEOUT, 10);
    
    $config = parse_ini_file('/etc/ldap/config.ini', true);
    $username = $config['ldap']['username'];
    $password = $config['ldap']['password'];
    
    // ok: php-ldap-bind-without-password
    if (ldap_bind($connection, $username, $password)) {
        $base_dn = "ou=groups,dc=internal,dc=net";
        $filter = "(cn=*)";
        $search = ldap_search($connection, $base_dn, $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_9() {
    $ldapconfig['host'] = 'ldap.example.com';
    $ldapconfig['port'] = 389;
    $ldapconfig['user'] = 'cn=admin,dc=example,dc=com';
    $ldapconfig['pass'] = getSecurePassword(); // Function to retrieve password securely
    
    $ds = ldap_connect($ldapconfig['host'], $ldapconfig['port']);
    
    // ok: php-ldap-bind-without-password
    $bind = @ldap_bind($ds, $ldapconfig['user'], $ldapconfig['pass']);
    
    if ($bind) {
        $searchFilter = "(objectClass=user)";
        $baseDN = "dc=example,dc=com";
        $result = ldap_search($ds, $baseDN, $searchFilter);
    }
}
// {/fact}

function getSecurePassword() {
    // This would retrieve password from a secure source
    return $_ENV['LDAP_ADMIN_PASSWORD'];
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_10() {
    $ldap = ldap_connect("ldap://directory.example.org");
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
    
    $credentials = json_decode(file_get_contents('/var/secrets/ldap_creds.json'), true);
    $bind_dn = $credentials['username'];
    $bind_password = $credentials['password'];
    
    // ok: php-ldap-bind-without-password
    $bind_result = ldap_bind($ldap, $bind_dn, $bind_password);
    
    if ($bind_result) {
        $search_filter = "(mail=*)";
        $base_dn = "ou=people,dc=example,dc=org";
        $search_result = ldap_search($ldap, $base_dn, $search_filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_11() {
    $server = "ldap.company.local";
    $connection = ldap_connect($server);
    
    if ($connection) {
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        $bind_dn = "cn=service_account,ou=service_accounts,dc=company,dc=local";
        $bind_password = getPasswordFromVault('ldap_service_account');
        
        // ok: php-ldap-bind-without-password
        $bind = ldap_bind($connection, $bind_dn, $bind_password);
        
        if ($bind) {
            $search_base = "ou=departments,dc=company,dc=local";
            $search_filter = "(department=*)";
            $result = ldap_search($connection, $search_base, $search_filter);
        }
    }
}
// {/fact}

function getPasswordFromVault($key) {
    // This would retrieve password from a secure vault
    $vault_data = json_decode(file_get_contents('/path/to/secure/vault.json'), true);
    return $vault_data[$key];
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_12() {
    $ldap_server = "ldap://auth.example.net";
    $ds = ldap_connect($ldap_server);
    
    if (!$ds) {
        echo "Unable to connect to LDAP server";
        exit;
    }
    
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Validate credentials before binding
    if (empty($username) || empty($password)) {
        echo "Username and password required";
        exit;
    }
    
    // ok: php-ldap-bind-without-password
    $bind = ldap_bind($ds, "uid=$username,ou=users,dc=example,dc=net", $password);
    
    if ($bind) {
        $filter = "(uid=$username)";
        $result = ldap_search($ds, "ou=users,dc=example,dc=net", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_13() {
    $ldap_uri = "ldap://directory.example.com:389";
    $ldap = ldap_connect($ldap_uri);
    
    if ($ldap) {
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        $bind_dn = "cn=application,ou=services,dc=example,dc=com";
        $bind_password = getCredentialFromSecureStore('ldap_app_password');
        
        // ok: php-ldap-bind-without-password
        $is_bound = ldap_bind($ldap, $bind_dn, $bind_password);
        
        if ($is_bound) {
            $base_dn = "dc=example,dc=com";
            $filter = "(objectClass=posixAccount)";
            $search = ldap_search($ldap, $base_dn, $filter);
        }
    }
}
// {/fact}

function getCredentialFromSecureStore($key) {
    // Simulating retrieval from a secure credential store
    $store = [
        'ldap_app_password' => $_ENV['LDAP_APP_PASSWORD']
    ];
    return $store[$key];
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_14() {
    $ldap_connection = ldap_connect("ldap://ldap.example.org");
    
    if (!$ldap_connection) {
        die("Could not connect to LDAP server");
    }
    
    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // Get credentials from a secure source
    $config = require('/etc/app/config.php');
    $bind_dn = $config['ldap']['bind_dn'];
    $bind_password = $config['ldap']['bind_password'];
    
    // ok: php-ldap-bind-without-password
    $bind = ldap_bind($ldap_connection, $bind_dn, $bind_password);
    
    if ($bind) {
        $email = $_POST['email'];
        $filter = "(mail=$email)";
        $result = ldap_search($ldap_connection, "ou=staff,dc=example,dc=org", $filter);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_15() {
    $ldap_host = "ldap.internal.example.com";
    $ldap = ldap_connect($ldap_host);
    
    if ($ldap === false) {
        return false;
    }
    
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, 5);
    
    // Use SASL authentication
    $sasl_username = $_SERVER['PHP_AUTH_USER'];
    $sasl_password = $_SERVER['PHP_AUTH_PW'];
    
    // ok: php-ldap-bind-without-password
    $bind_result = ldap_sasl_bind($ldap, null, $sasl_password, 'DIGEST-MD5', null, $sasl_username, null);
    
    if ($bind_result) {
        $base_dn = "ou=users,dc=internal,dc=example,dc=com";
        $search = ldap_search($ldap, $base_dn, "(uid=$sasl_username)");
    }
}
// {/fact}
?>
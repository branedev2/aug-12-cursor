import javax.naming.Context
import javax.naming.directory.{DirContext, InitialDirContext, SearchControls}
import java.util.{Hashtable, Properties}
import javax.naming.ldap.{InitialLdapContext, LdapContext}

object InsecureLDAPConfigurationExamples {

  // True Positives (Vulnerable Code)

  def bad_case_1(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=example,dc=com")
    // No authentication specified - anonymous bind
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=users", "(uid=user)", searchControls)
  }

  def bad_case_2(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldapserver:389/o=JNDITutorial")
    env.put(Context.SECURITY_AUTHENTICATION, "none")
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    ctx.search("ou=users", "(uid=user)", searchControls)
  }

  def bad_case_3(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "password")
    
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    // Setting returning object flag to true is insecure
    // ruleid: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=people", "(objectClass=person)", searchControls)
  }

  def bad_case_4(): Unit = {
    val props = new Properties()
    props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.put(Context.PROVIDER_URL, "ldap://ldap.example.org:389")
    // Anonymous bind - no authentication
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(props, null)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(true)
    ctx.search("dc=example,dc=org", "(cn=*)", searchControls)
  }

  def bad_case_5(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.company.com:389/dc=company,dc=com")
    // No authentication specified
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    ctx.search("ou=employees", "(sn=Smith)", searchControls)
  }

  def bad_case_6(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldaps://secure-ldap.example.com:636")
    // Even with LDAPS, anonymous bind is still insecure
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    ctx.search("ou=groups", "(objectClass=groupOfNames)", searchControls)
  }

  def bad_case_7(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.example.net:389")
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=reader,dc=example,dc=net")
    env.put(Context.SECURITY_CREDENTIALS, "readerpass")
    
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    // Setting returning object flag to true is insecure
    // ruleid: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=users", "(mail=*@example.net)", searchControls)
  }

  def bad_case_8(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://corporate-ldap:389/dc=corporate,dc=local")
    // Using "none" authentication is insecure
    env.put(Context.SECURITY_AUTHENTICATION, "none")
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(env, null)
    val searchControls = new SearchControls()
    ctx.search("ou=departments", "(departmentNumber=*)", searchControls)
  }

  def bad_case_9(): Unit = {
    val env = new Hashtable[String, Object]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.example.org:389")
    // No authentication
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=services", "(objectClass=device)", searchControls)
  }

  def bad_case_10(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.internal:389")
    // Authentication is set but to an insecure method
    env.put(Context.SECURITY_AUTHENTICATION, "none")
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    ctx.search("ou=applications", "(objectClass=application)", searchControls)
  }

  def bad_case_11(): Unit = {
    val props = new Properties()
    props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.put(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    props.put(Context.SECURITY_AUTHENTICATION, "simple")
    props.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
    props.put(Context.SECURITY_CREDENTIALS, "adminpass")
    
    val ctx = new InitialDirContext(props)
    val searchControls = new SearchControls()
    // Setting returning object flag to true is insecure
    // ruleid: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=system", "(objectClass=*)", searchControls)
  }

  def bad_case_12(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://auth.company.com:389")
    // No authentication specified - anonymous bind
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    ctx.search("ou=roles", "(cn=admin)", searchControls)
  }

  def bad_case_13(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.example.org:389")
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "uid=user,ou=people,dc=example,dc=org")
    env.put(Context.SECURITY_CREDENTIALS, "userpass")
    
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    // Setting returning object flag to true is insecure
    // ruleid: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=groups", "(member=*)", searchControls)
  }

  def bad_case_14(): Unit = {
    val env = new Hashtable[String, Object]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.internal:389")
    // Using "none" authentication is insecure
    env.put(Context.SECURITY_AUTHENTICATION, "none")
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(env, null)
    val searchControls = new SearchControls()
    ctx.search("dc=internal", "(uid=*)", searchControls)
  }

  def bad_case_15(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.company.net:389")
    // No authentication specified
    // ruleid: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(true)
    ctx.search("ou=contractors", "(objectClass=person)", searchControls)
  }

  // True Negatives (Secure Code)

  def good_case_1(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=example,dc=com")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "adminpassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=users", "(uid=user)", searchControls)
  }

  def good_case_2(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldapserver:389/o=JNDITutorial")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=Directory Manager")
    env.put(Context.SECURITY_CREDENTIALS, "password")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=users", "(uid=user)", searchControls)
  }

  def good_case_3(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "password")
    
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    // Setting returning object flag to false is secure
    // ok: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=people", "(objectClass=person)", searchControls)
  }

  def good_case_4(): Unit = {
    val props = new Properties()
    props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.put(Context.PROVIDER_URL, "ldap://ldap.example.org:389")
    // Using secure authentication
    props.put(Context.SECURITY_AUTHENTICATION, "simple")
    props.put(Context.SECURITY_PRINCIPAL, "cn=manager,dc=example,dc=org")
    props.put(Context.SECURITY_CREDENTIALS, "managerpassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(props, null)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("dc=example,dc=org", "(cn=*)", searchControls)
  }

  def good_case_5(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.company.com:389/dc=company,dc=com")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "uid=reader,ou=system,dc=company,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "readerpassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=employees", "(sn=Smith)", searchControls)
  }

  def good_case_6(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldaps://secure-ldap.example.com:636")
    // Using secure authentication with LDAPS
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=reader,dc=example,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "readerpass")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=groups", "(objectClass=groupOfNames)", searchControls)
  }

  def good_case_7(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.example.net:389")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=reader,dc=example,dc=net")
    env.put(Context.SECURITY_CREDENTIALS, "readerpass")
    
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    // Setting returning object flag to false is secure
    // ok: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=users", "(mail=*@example.net)", searchControls)
  }

  def good_case_8(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://corporate-ldap:389/dc=corporate,dc=local")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=app,ou=services,dc=corporate,dc=local")
    env.put(Context.SECURITY_CREDENTIALS, "apppassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(env, null)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=departments", "(departmentNumber=*)", searchControls)
  }

  def good_case_9(): Unit = {
    val env = new Hashtable[String, Object]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.example.org:389")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=admins,dc=example,dc=org")
    env.put(Context.SECURITY_CREDENTIALS, "adminpassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=services", "(objectClass=device)", searchControls)
  }

  def good_case_10(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.internal:389")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=service,ou=services,dc=internal")
    env.put(Context.SECURITY_CREDENTIALS, "servicepass")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=applications", "(objectClass=application)", searchControls)
  }

  def good_case_11(): Unit = {
    val props = new Properties()
    props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.put(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    // Using secure authentication
    props.put(Context.SECURITY_AUTHENTICATION, "simple")
    props.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
    props.put(Context.SECURITY_CREDENTIALS, "adminpass")
    
    val ctx = new InitialDirContext(props)
    val searchControls = new SearchControls()
    // Setting returning object flag to false is secure
    // ok: scala-insecure-ldap-configuration
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=system", "(objectClass=*)", searchControls)
  }

  def good_case_12(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://auth.company.com:389")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "uid=app,ou=applications,dc=company,dc=com")
    env.put(Context.SECURITY_CREDENTIALS, "apppassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=roles", "(cn=admin)", searchControls)
  }

  def good_case_13(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.example.org:389")
    // Using stronger authentication - DIGEST-MD5
    env.put(Context.SECURITY_AUTHENTICATION, "DIGEST-MD5")
    env.put(Context.SECURITY_PRINCIPAL, "uid=user,ou=people,dc=example,dc=org")
    env.put(Context.SECURITY_CREDENTIALS, "userpass")
    
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=groups", "(member=*)", searchControls)
  }

  def good_case_14(): Unit = {
    val env = new Hashtable[String, Object]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldaps://directory.internal:636")
    // Using secure authentication with LDAPS
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=service,ou=services,dc=internal")
    env.put(Context.SECURITY_CREDENTIALS, "servicepassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialLdapContext(env, null)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("dc=internal", "(uid=*)", searchControls)
  }

  def good_case_15(): Unit = {
    val env = new Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://ldap.company.net:389")
    // Using secure authentication
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, "cn=reader,ou=services,dc=company,dc=net")
    env.put(Context.SECURITY_CREDENTIALS, "readerpassword")
    // ok: scala-insecure-ldap-configuration
    val ctx = new InitialDirContext(env)
    val searchControls = new SearchControls()
    searchControls.setReturningObjFlag(false)
    ctx.search("ou=contractors", "(objectClass=person)", searchControls)
  }
}
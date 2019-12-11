---
title: "OWASP Top 10: The Ten Most Critical Web App Vulnerabilities"
author: Brandon Silver
date: 2019-12-11
---

## What's OWASP?
-  **O**pen **W**eb **A**pplication **S**ecurity **P**roject 
- "... a [501(c)(3)](https://www.irs.gov/charities-non-profits/charitable-organizations/exemption-requirements-section-501c3-organizations) worldwide not-for-profit charitable organization focused on improving the security of software. "
- <https://www.owasp.org/>


## What's the OWASP Top 10?
- The most critical vulnerabilities according to a survey of security firms
- Also based on real-world vulnerabilities and data breaches

## The Top 10 (1-5)
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control


## The Top 10 (6-10)
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring


## 1. Injection {.centered}
Untrusted data is provided to an interpreter.


## 1. Injection: Attack Vectors
- SQL query parameters
- LDAP query parameters
- OS command (external process call) parameters


## 1. Injection: Mitigation
- Properly validate all untrusted data prior to use
- Use prepared statements for SQL queries (DO NOT concatenate parameters into
  query strings!)


## 1. Injection
**VULNERABLE:**

    Statement stmt = con.createStatement();
    stmt.execute("SELECT * FROM users WHERE id = " + id);


## 1. Injection
**FIXED:**

    String sql = "SELECT * FROM users WHERE id = ?";
    PreparedStatement ps = con.prepareStatement(sql);
    ps.setInt(1, DBSecurityValidator.validateSafe(id));
    ps.execute();


## 2. Broken Authentication {.centered}
Authentication mechanisms are broken, allowing attackers to assume other users'
identities. 


## 2. Broken Authentication: Attack Vectors
- Brute force / automated password lookups
- weak password recovery systems
- storage of plaintext or weakly hashed passwords


## 2. Broken Authentication: Mitigation
- Multi-factor authentication
- check for weak passwords
- Hash & salt users' passwords *using an appropriate algorithm* (ex:
  [bcrypt](https://en.wikipedia.org/wiki/Bcrypt))


## 3. Sensitive Data Exposure {.centered}
Not encrypting sensitive data at rest or in transit, or using poor(ly
implemented) encryption.


## 3. Sensitive Data Exposure: Attack Vectors
- Man-in-the-middle attacks
- client or server compromise
- cryptanalysis of captured ciphertext
- decryption using improperly-used default keys
- failure to verify SSL/TLS certificates


## 3. Sensitive Data Exposure: Mitigation
- Don't store unnecessary sensitive data
- Appropriately encrypt or hash sensitive data at rest and in transit.
- Use strong crypto suites and protocols that are *implemented correctly*


## 4. XML External Entities (XXE) {.centered}
Vulnerable XML processors dereference and evaluate external URIs.


## 4. XML External Entities (XXE): Attack Vectors
XML documents from untrusted sources (especially SOAP-based web services)


## 4. XML External Entities (XXE): Mitigation
- Use less complex data formats like JSON
- Make sure all XML processing libraries are up-to-date
- Use SOAP >= 1.2
- Disable XML external entity and DTD processing in XML processors


## 4. XML External Entities (XXE): Example Attack
    <?xml version="1.0" encoding="ISO-8859-1"?>

    <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>


## 5. Broken Access Control {.centered}
Flaws in the system used for controlling user access.


## 5. Broken Access Control: Attack Vectors
- Bypassing client-side only validation
- Exploiting CORS misconfiguration
- Metadata manipulation (cookies, JWTs, etc)
- Unsecured API endpoints


## 5. Broken Access Control: Mitigation
- Unit and integration testing of authentication & authorization
- Require authentication & authorization for all API endpoints
- Use a single (*verified*) approach to access control & reuse it
- Log & notify on access control failures


## 6. Security Misconfiguration {.centered}
A misconfiguration across any part of the application stack.


## 6. Security Misconfiguration: Attack Vectors
- Unnecessary features are enabled or installed
- Default account credentials
- Weakly secured app servers
- Missing security headers in server responses


## 6. Security Misconfiguration: Mitigation
- A repeatable hardening process
- Minimal software deployments (whole stack)
- Procedures to verify configurations
- Segmentation in application infrastructure
- Use the most strict client HTTP security headers


## 7. Cross-Site Scripting (XSS) {.centered}
Untrusted and unescaped input is included in the UI, allowing an attacker to
control client-side functionality. 


## 7. Cross-Site Scripting (XSS): Attack Vectors
- Reflected XSS: unsanitized user input is returned in the response to that
  input
- Stored XSS: unsanitized user input is stored in the DB and viewed at a later
  time by another user or an admin
- DOM XSS: JS frameworks, SPAs, and APIs dynamically include unsanitized user
  input in the client side


## 7. Cross-Site Scripting (XSS): Mitigation
- Use a modern framework that automatically escapes XSS by design (!)
- Sanitize untrusted user input based on its context in the output
- Enable a [Content Security Policy
  (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)


## 8. Insecure Deserialization {.centered}
Serialized objects from untrusted sources are deserialized by the application.


## 8. Insecure Deserialization: Attack Vectors
- "Super" Cookies: user state containing key app metadata is modified by an
  attacker to e.g. escalate privileges


## 8. Insecure Deserialization: Mitigation
- Do not deserialize untrusted serialized objects (best)
- Enforce strict type safety during deserialization 
- Run object deserialization code in an isolated environment
- Alert if a user deserializes constantly


## 9. Using Components with Known Vulnerabilities {.centered}
Including third-party dependencies that contain known security bugs.


## 9. Using Components with Known Vulnerabilities: Mitigation
- Remove any unneeded dependencies or features
- Continuously check used components for vulnerability reports and security
  updates
- Keep components up to date


## 10. Insufficient Logging & Monitoring {.centered}
Attacks proceed and expand without the knowledge of the target.


## 10. Insufficient Logging & Monitoring: Mitigation
- Log input validation failures, failed logins, and errors in enough detail to
  identify malicious behavior
- Structure logs so that they can be used with log management solutions
- Monitor logs and alert when suspicious behavior is detected


## One more thing... {.centered}


## What about Cross-Site Request Forgery (CSRF)? 
- Essentially a solved problem (except in legacy frameworks...)
- For legacy frameworks, several approaches to mitigate (eg. Double-Submit Cookie
  Pattern)


## The Top 10 (1-5)
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control


## The Top 10 (6-10)
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring


## Questions? 
- Ask 'em now!
- Or email [me](mailto:bsilver@freax.sh) later!
- slides: <https://github.com/brandonsilver/slides>


## Sources
- [OWASP Top 10 - 2017](https://www.owasp.org/index.php/Top_10-2017_Top_10) 
- The same, but in easy-to-read PDF form (recommended):
  <https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf> 

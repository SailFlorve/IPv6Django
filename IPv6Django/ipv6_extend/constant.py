import dataclasses


@dataclasses.dataclass
class Constant:
    LIB_TREE_PATH = "lib/6tree_mod_2"
    LIB_ZMAP_PATH = "zmap"

    TREE_DIR_PATH = "tree_hex"
    RESULT_DIR_PATH = "result"

    SEEDS_NAME = f"seeds_hex"

    UPLOAD_DIR_PATH = "upload"

    TARGET_DIR_PATH = "targets"
    TARGET_TMP_PATH = "targets.txt"
    RESULT_TMP_PATH = "result.txt"

    DEFAULT_PORTS = "443"

    DEFAULT_BUDGET: int = 300000
    DEFAULT_PROBE = "icmp6_echoscan"

    LOG_FILE_NAME = "output_log.txt"
    SCAN_RES_NAME = "scan_result"

    ACTIVE_ADDR_FILE = "discovered_addrs"

    SCRIPT_DIR_PATH = '/usr/share/nmap/scripts'

    vuln_scripts = [('afp-path-vuln', 'Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.'),
                    (
                        'broadcast-avahi-dos',
                        'Attempts to discover hosts in the local network using the DNS Service\nDiscovery protocol and sends a NULL UDP packet to each host to test\nif it is vulnerable to the Avahi NULL UDP packet denial of service\n(CVE-2011-1002).'),
                    ('clamav-exec', 'Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.'),
                    (
                        'distcc-cve2004-2687',
                        'Detects and exploits a remote code execution vulnerability in the distributed\ncompiler daemon distcc. The vulnerability was disclosed in 2002, but is still\npresent in modern implementation due to poor configuration of the service.'),
                    ('dns-update', 'Attempts to perform a dynamic DNS update without authentication.'),
                    ('firewall-bypass',
                     'Detects a vulnerability in netfilter and other firewalls that use helpers to\ndynamically open ports for protocols such as ftp and sip.'),
                    ('ftp-libopie',
                     'Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),\na vulnerability discovered by Maksymilian Arciemowicz and Adam "pi3" Zabrocki.\nSee the advisory at'),
                    ('ftp-proftpd-backdoor',
                     'Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID\n45150. This script attempts to exploit the backdoor using the innocuous'),
                    ('ftp-vsftpd-backdoor',
                     'Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04\n(CVE-2011-2523). This script attempts to exploit the backdoor using the\ninnocuous'),
                    ('ftp-vuln-cve2010-4221',
                     'Checks for a stack-based buffer overflow in the ProFTPD server, version\nbetween 1.3.2rc3 and 1.3.3b. By sending a large number of TELNET_IAC escape\nsequence, the proftpd process miscalculates the buffer length, and a remote\nattacker will be able to corrupt the stack and execute arbitrary code within\nthe context of the proftpd process (CVE-2010-4221). Authentication is not\nrequired to exploit this vulnerability.'),
                    ('http-adobe-coldfusion-apsa1301',
                     "Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion\nservers to retrieve a valid administrator's session cookie."),
                    ('http-aspnet-debug',
                     'Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request.'),
                    ('http-avaya-ipoffice-users', 'Attempts to enumerate users in Avaya IP Office systems 7.x.'),
                    (
                        'http-awstatstotals-exec',
                        'Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14\nand possibly other products based on it (CVE: 2008-3922).'),
                    ('http-axis2-dir-traversal',
                     'Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by\nsending a specially crafted request to the parameter'),
                    ('http-cookie-flags',
                     'Examines cookies set by HTTP services.  Reports any session cookies set\nwithout the httponly flag.  Reports any session cookies set over SSL without\nthe secure flag.  If http-enum.nse is also run, any interesting paths found\nby it will be checked in addition to the root.'),
                    ('http-cross-domain-policy',
                     'Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)\nin web applications and lists the trusted domains. Overly permissive settings enable Cross Site Request Forgery\nattacks and may allow attackers to access sensitive data. This script is useful to detect permissive\nconfigurations and possible domain names available for purchase to exploit the application.'),
                    ('http-csrf', 'This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.'),
                    ('http-dlink-backdoor',
                     'Detects a firmware backdoor on some D-Link routers by changing the User-Agent\nto a "secret" value. Using the "secret" User-Agent bypasses authentication\nand allows admin access to the router.'),
                    ('http-dombased-xss',
                     'It looks for places where attacker-controlled information in the DOM may be used\nto affect JavaScript execution in certain ways. The attack is explained here:'),
                    ('http-enum', 'Enumerates directories used by popular web applications and servers.'),
                    ('http-fileupload-exploiter',
                     'Exploits insecure file upload forms in web applications\nusing various techniques like changing the Content-type\nheader or creating valid image files containing the\npayload in the comment.'),
                    ('http-frontpage-login',
                     'Checks whether target machines are vulnerable to anonymous Frontpage login.'),
                    ('http-git',
                     "Checks for a Git repository found in a website's document root\n/.git/<something>) and retrieves as much repo information as\npossible, including language/framework, remotes, last commit\nmessage, and repository description."),
                    ('http-huawei-hg5xx-vuln',
                     'Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...)\nvulnerable to a remote credential and information disclosure vulnerability. It\nalso extracts the PPPoE credentials and other interesting configuration values.'),
                    ('http-iis-webdav-vuln',
                     'Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access\nsecured WebDAV folders by searching for a password-protected folder and\nattempting to access it. This vulnerability was patched in Microsoft Security\nBulletin MS09-020,'),
                    ('http-internal-ip-disclosure',
                     'Determines if the web server leaks its internal IP address when sending an HTTP/1.0 request without a Host header.'),
                    ('http-jsonp-detection',
                     'Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be\nused to bypass Same-origin Policy restrictions in web browsers.'),
                    ('http-litespeed-sourcecode-download',
                     "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x\nbefore 4.0.15 to retrieve the target script's source code by sending a HTTP\nrequest with a null byte followed by a .txt file extension (CVE-2010-2333)."),
                    ('http-majordomo2-dir-traversal',
                     'Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).'),
                    (
                        'http-method-tamper',
                        'Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering.\nIf an array of paths to check is not set, it will crawl the web server and perform the check against any\npassword protected resource that it finds.'),
                    ('http-passwd',
                     'Checks if a web server is vulnerable to directory traversal by attempting to\nretrieve'),
                    (
                        'http-phpmyadmin-dir-traversal',
                        'Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and\npossibly other versions) to retrieve remote files on the web server.'),
                    ('http-phpself-xss',
                     'Crawls a web server and attempts to find PHP files vulnerable to reflected\ncross site scripting via the variable'),
                    ('http-shellshock',
                     'Attempts to exploit the "shellshock" vulnerability (CVE-2014-6271 and\nCVE-2014-7169) in web applications.'),
                    (
                        'http-slowloris-check',
                        'Tests a web server for vulnerability to the Slowloris DoS attack without\nactually launching a DoS attack.'),
                    (
                        'http-sql-injection',
                        'Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL\ninjection attack. It also extracts forms from found websites and tries to identify\nfields that are vulnerable.'),
                    (
                        'http-stored-xss',
                        "Unfiltered '>' (greater than sign). An indication of potential XSS vulnerability."),
                    (
                        'http-tplink-dir-traversal',
                        'Exploits a directory traversal vulnerability existing in several TP-Link\nwireless routers. Attackers may exploit this vulnerability to read any of the\nconfiguration and password files remotely and without authentication.'),
                    ('http-trace',
                     'Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug\nis enabled, it returns the header fields that were modified in the response.'),
                    (
                        'http-vmware-path-vuln',
                        'Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).'),
                    ('http-vuln-cve2006-3392', 'Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)'),
                    ('http-vuln-cve2009-3960',
                     'Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.'),
                    (
                        'http-vuln-cve2010-0738',
                        'Tests whether a JBoss target is vulnerable to jmx console authentication bypass (CVE-2010-0738).'),
                    (
                        'http-vuln-cve2010-2861',
                        'Executes a directory traversal attack against a ColdFusion\nserver and tries to grab the password hash for the administrator user. It\nthen uses the salt value (hidden in the web page) to create the SHA1\nHMAC hash that the web server needs for authentication as admin. You can\npass this value to the ColdFusion server as the admin without cracking\nthe password hash.'),
                    ('http-vuln-cve2011-3192',
                     'Detects a denial of service vulnerability in the way the Apache web server\nhandles requests for multiple overlapping/simple ranges of a page.'),
                    ('http-vuln-cve2011-3368',
                     "Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP server's reverse proxy mode.\nThe script will run 3 tests:"),
                    ('http-vuln-cve2012-1823',
                     'Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This\ncritical vulnerability allows attackers to retrieve source code and execute\ncode remotely.'),
                    ('http-vuln-cve2013-0156',
                     'Detects Ruby on Rails servers vulnerable to object injection, remote command\nexecutions and denial of service attacks. (CVE-2013-0156)'),
                    ('http-vuln-cve2013-6786',
                     'Detects a URL redirection and reflected XSS vulnerability in Allegro RomPager\nWeb server. The vulnerability has been assigned CVE-2013-6786.'),
                    ('http-vuln-cve2013-7091',
                     'An 0 day was released on the 6th December 2013 by rubina119, and was patched in Zimbra 7.2.6.'),
                    (
                        'http-vuln-cve2014-2126',
                        'Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA ASDM\nPrivilege Escalation Vulnerability (CVE-2014-2126).'),
                    ('http-vuln-cve2014-2127',
                     'Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN\nPrivilege Escalation Vulnerability (CVE-2014-2127).'),
                    ('http-vuln-cve2014-2128',
                     'Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN\nAuthentication Bypass Vulnerability (CVE-2014-2128).'),
                    ('http-vuln-cve2014-2129',
                     'Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP\nDenial of Service Vulnerability (CVE-2014-2129).'),
                    ('http-vuln-cve2014-3704',
                     "Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32\nof Drupal core are known to be affected."),
                    ('http-vuln-cve2014-8877',
                     'Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM\nDownload Manager plugin. Versions <= 2.0.0 are known to be affected.'),
                    ('http-vuln-cve2015-1427',
                     'This script attempts to detect a vulnerability, CVE-2015-1427, which  allows attackers\n to leverage features of this API to gain unauthenticated remote code execution (RCE).'),
                    ('http-vuln-cve2015-1635',
                     'Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635).'),
                    (
                        'http-vuln-cve2017-1001000',
                        'Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1 that\nallows unauthenticated users to inject content in posts.'),
                    ('http-vuln-cve2017-5638',
                     'Detects whether the specified URL is vulnerable to the Apache Struts\nRemote Code Execution Vulnerability (CVE-2017-5638).'),
                    ('http-vuln-cve2017-5689',
                     'Detects if a system with Intel Active Management Technology is vulnerable to the INTEL-SA-00075\nprivilege escalation vulnerability (CVE2017-5689).'),
                    ('http-vuln-cve2017-8917',
                     'An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows for\nunauthenticated users to execute arbitrary SQL commands. This vulnerability was\ncaused by a new component,'),
                    ('http-vuln-misfortune-cookie',
                     'Detects the RomPager 4.07 Misfortune Cookie vulnerability by safely exploiting it.'),
                    ('http-vuln-wnr1000-creds',
                     'A vulnerability has been discovered in WNR 1000 series that allows an attacker\nto retrieve administrator credentials with the router interface.\nTested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA'),
                    ('http-wordpress-users',
                     'Enumerates usernames in Wordpress blog/CMS installations by exploiting an\ninformation disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1,\n3.1.3 and 3.2-beta2 and possibly others.'),
                    ('ipmi-cipher-zero',
                     'IPMI 2.0 Cipher Zero Authentication Bypass Scanner. This module identifies IPMI 2.0\n  compatible systems that are vulnerable to an authentication bypass vulnerability\n  through the use of cipher zero.'),
                    ('irc-botnet-channels',
                     'Checks an IRC server for channels that are commonly used by malicious botnets.'),
                    (
                        'irc-unrealircd-backdoor',
                        'Checks if an IRC server is backdoored by running a time-based command (ping)\nand checking how long it takes to respond.'),
                    ('mysql-vuln-cve2012-2122', ''),
                    ('netbus-auth-bypass',
                     'Checks if a NetBus server is vulnerable to an authentication bypass\nvulnerability which allows full access without knowing the password.'),
                    ('puppet-naivesigning',
                     'Detects if naive signing is enabled on a Puppet server. This enables attackers\nto create any Certificate Signing Request and have it signed, allowing them\nto impersonate as a puppet agent. This can leak the configuration of the agents\nas well as any other sensitive information found in the configuration files.'),
                    ('qconn-exec',
                     'Attempts to identify whether a listening QNX QCONN daemon allows\nunauthenticated users to execute arbitrary operating system commands.'),
                    ('rdp-vuln-ms12-020', 'Checks if a machine is vulnerable to MS12-020 RDP vulnerability.'),
                    ('realvnc-auth-bypass',
                     'Checks if a VNC server is vulnerable to the RealVNC authentication bypass\n(CVE-2006-2369).'),
                    ('rmi-vuln-classloader',
                     'Tests whether Java rmiregistry allows class loading.  The default\nconfiguration of rmiregistry allows loading classes from remote URLs,\nwhich can lead to remote code execution. The vendor (Oracle/Sun)\nclassifies this as a design feature.'),
                    ('rsa-vuln-roca',
                     'Detects RSA keys vulnerable to Return Of Coppersmith Attack (ROCA) factorization.'),
                    (
                        'samba-vuln-cve-2012-1182',
                        'Checks if target machines are vulnerable to the Samba heap overflow vulnerability CVE-2012-1182.'),
                    ('smb-double-pulsar-backdoor',
                     'Checks if the target machine is running the Double Pulsar SMB backdoor.'),
                    (
                        'smb-vuln-conficker',
                        'Detects Microsoft Windows systems infected by the Conficker worm. This check is dangerous and\nit may crash systems.'),
                    ('smb-vuln-cve-2017-7494',
                     'Checks if target machines are vulnerable to the arbitrary shared library load\nvulnerability CVE-2017-7494.'),
                    (
                        'smb-vuln-cve2009-3103',
                        'Detects Microsoft Windows systems vulnerable to denial of service (CVE-2009-3103).\nThis script will crash the service if it is vulnerable.'),
                    ('smb-vuln-ms06-025',
                     'Detects Microsoft Windows systems with Ras RPC service vulnerable to MS06-025.'),
                    ('smb-vuln-ms07-029',
                     'Detects Microsoft Windows systems with Dns Server RPC vulnerable to MS07-029.'),
                    (
                        'smb-vuln-ms08-067',
                        'Detects Microsoft Windows systems vulnerable to the remote code execution vulnerability\nknown as MS08-067. This check is dangerous and it may crash systems.'),
                    ('smb-vuln-ms10-054',
                     'Tests whether target machines are vulnerable to the ms10-054 SMB remote memory\ncorruption vulnerability.'),
                    (
                        'smb-vuln-ms10-061',
                        'Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability.'),
                    (
                        'smb-vuln-ms17-010',
                        'Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code\n execution vulnerability (ms17-010, a.k.a. EternalBlue).\n The vulnerability is actively exploited by WannaCry and Petya ransomware and other malware.'),
                    ('smb-vuln-regsvc-dos',
                     'Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc caused by a null pointer\ndereference. This check will crash the service if it is vulnerable and requires a guest account or\nhigher to work.'),
                    (
                        'smb-vuln-webexec',
                        'A critical remote code execution vulnerability exists in WebExService (WebExec).'),
                    (
                        'smb2-vuln-uptime',
                        'Attempts to detect missing patches in Windows systems by checking the\nuptime returned during the SMB2 protocol negotiation.'),
                    ('smtp-vuln-cve2010-4344',
                     'Checks for and/or exploits a heap overflow within versions of Exim\nprior to version 4.69 (CVE-2010-4344) and a privilege escalation\nvulnerability in Exim 4.72 and prior (CVE-2010-4345).'),
                    ('smtp-vuln-cve2011-1720',
                     'Checks for a memory corruption in the Postfix SMTP server when it uses\nCyrus SASL library authentication mechanisms (CVE-2011-1720).  This\nvulnerability can allow denial of service and possibly remote code\nexecution.'),
                    ('smtp-vuln-cve2011-1764',
                     'Checks for a format string vulnerability in the Exim SMTP server\n(version 4.70 through 4.75) with DomainKeys Identified Mail (DKIM) support\n(CVE-2011-1764).  The DKIM logging mechanism did not use format string\nspecifiers when logging some parts of the DKIM-Signature header field.\nA remote attacker who is able to send emails, can exploit this vulnerability\nand execute arbitrary code with the privileges of the Exim daemon.'),
                    ('ssl-ccs-injection',
                     'Detects whether a server is vulnerable to the SSL/TLS "CCS Injection"\nvulnerability (CVE-2014-0224), first discovered by Masashi Kikuchi.\nThe script is based on the ccsinjection.c code authored by Ramon de C Valle\n('),
                    ('ssl-cert-intaddr',
                     "Reports any private (RFC1918) IPv4 addresses found in the various fields of\nan SSL service's certificate.  These will only be reported if the target\naddress itself is not private.  Nmap v7.30 or later is required."),
                    ('ssl-dh-params', 'Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.'),
                    ('ssl-heartbleed',
                     'Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).\nThe code is based on the Python script ssltest.py authored by Katie Stafford (katie@ktpanda.org)'),
                    ('ssl-known-key',
                     'Checks whether the SSL certificate used by a host has a fingerprint\nthat matches an included database of problematic keys.'),
                    ('ssl-poodle', 'Checks whether SSLv3 CBC ciphers are allowed (POODLE)'),
                    ('sslv2-drown',
                     'Determines whether the server supports SSLv2, what ciphers it supports and tests for\nCVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)'),
                    ('supermicro-ipmi-conf',
                     'Attempts to download an unprotected configuration file containing plain-text\nuser credentials in vulnerable Supermicro Onboard IPMI controllers.'),
                    (
                        'tls-ticketbleed',
                        'Detects whether a server is vulnerable to the F5 Ticketbleed bug (CVE-2016-9244).'),
                    ('vulners',
                     'For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.'),
                    ('wdb-version',
                     'Detects vulnerabilities and gathers information (such as version\nnumbers and hardware support) from VxWorks Wind DeBug agents.')]

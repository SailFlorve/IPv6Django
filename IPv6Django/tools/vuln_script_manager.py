import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.models import VulnScriptModel


class VulnScripts:
    vuln_scripts = [('ftp-libopie',
                     'Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),\na vulnerability discovered by Maksymilian Arciemowicz and Adam "pi3" Zabrocki.\nSee the advisory at'),
                    ('ftp-proftpd-backdoor',
                     'Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID\n45150. This script attempts to exploit the backdoor using the innocuous'),
                    ('ftp-vsftpd-backdoor',
                     'Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04\n(CVE-2011-2523). This script attempts to exploit the backdoor using the\ninnocuous'),
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
                    ('http-vuln-cve2015-1635',
                     'Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635).'),
                    (
                        'http-vuln-cve2017-1001000',
                        'Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1 that\nallows unauthenticated users to inject content in posts.'),
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
                    ('ssl-cert-intaddr',
                     "Reports any private (RFC1918) IPv4 addresses found in the various fields of\nan SSL service's certificate.  These will only be reported if the target\naddress itself is not private.  Nmap v7.30 or later is required."),
                    ('ssl-dh-params', 'Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.'),
                    ('ssl-heartbleed',
                     'Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).\nThe code is based on the Python script ssltest.py authored by Katie Stafford (katie@ktpanda.org)'),
                    ('ssl-known-key',
                     'Checks whether the SSL certificate used by a host has a fingerprint\nthat matches an included database of problematic keys.'),
                    ('ssl-poodle', 'Checks whether SSLv3 CBC ciphers are allowed (POODLE)'),
                    ('sslv2-drown',
                     'Determines whether the server supports SSLv2, what ciphers it supports and tests for\nCVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)')
                    ]


class VulnScriptManager:
    def __init__(self):
        pass

    @staticmethod
    def init_db_if_empty():
        if len(VulnScriptModel.objects.all()) != 0:
            return

        scripts_local = VulnScripts.vuln_scripts
        for script_tuple in scripts_local:
            model = VulnScriptModel(name=script_tuple[0], description=script_tuple[1])
            model.save()

    @staticmethod
    def load_scripts() -> list[VulnScriptModel]:
        result_list = []
        urlopen = urllib.request.urlopen("https://nmap.org/nsedoc/categories/vuln.html")
        bs4 = BeautifulSoup(urlopen.read())
        # bs4.findAll('dt')[0].next.next
        # bs4.findAll('dt')[0].nextSibling.next.next.next
        all_dt = bs4.findAll('dt')
        for dt in all_dt:
            vuln_name = str(dt.next.next).strip()
            vuln_des = str(dt.nextSibling.next.next.next).strip()
            result_list.append(VulnScriptModel(vuln_name, vuln_des))
        return result_list
import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.models import VulnScriptModel


class VulnScripts:
    vuln_scripts = [('http-dombased-xss',
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
        bs4 = BeautifulSoup(urlopen.read(), 'lxml')
        # bs4.findAll('dt')[0].next.next
        # bs4.findAll('dt')[0].nextSibling.next.next.next
        all_dt = bs4.findAll('dt')
        for dt in all_dt:
            vuln_name = str(dt.next.next).strip()
            vuln_des = str(dt.nextSibling.next.next.next).strip()
            result_list.append(VulnScriptModel(vuln_name, vuln_des))
        return result_list

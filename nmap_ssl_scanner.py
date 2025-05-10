# ---------------------------------------
# Sec-Sci SSL/TLS Scanner v1.250510 - May 2025
# ---------------------------------------
# Tool:      Sec-Sci SSL/TLS Scanner v1.250510
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender, IHttpListener, IScanIssue
import subprocess
import threading
import json
import urllib2
import os

hosts = []


def is_nmap_installed():
    try:
        output = subprocess.check_output(["nmap", "-V"], stderr=subprocess.STDOUT)
        return True
    except OSError:
        return False
    except subprocess.CalledProcessError:
        return True


def fetch_latest_issues(remote_ssl_issues_url):
    try:
        request = urllib2.Request(remote_ssl_issues_url)
        response = urllib2.urlopen(request, timeout=5)
        content = response.read()
        data = json.loads(content)
        local_file = "ssl_issues.json"

        # Write the new SSL Issues list to local file
        with open(local_file, 'w') as f:
            json.dump(data, f, indent=4)

        print("[INFO] Updated SSL Issues!")
        return data
    except Exception as e:
        print("[INFO] Failed to update SSL Issues from Remote: %s" % str(e))


def load_ssl_issues(local_file="ssl_issues.json"):
    if os.path.exists(local_file):
        try:
            with open(local_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print("[ERROR] Failed to load local issues file: %s" % str(e))
    return []  # Fallback to empty list if both remote and local fail


def run_nmap_ssl_scan(host, port, httpService, request_url, messageInfo, callbacks):
    # nmap_cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host]
    nmap_cmd = ["nmap", "-sV", "--script", "ssl*,tls*", "-p", str(port), host]

    # print("[INFO] Running Nmap command: {}".format(nmap_cmd))

    try:
        print("SSL Scan Started for " + host + ":" + str(port))
        nmap_output = subprocess.check_output(nmap_cmd, stderr=subprocess.STDOUT)
        nmap_output = nmap_output.decode("utf-8")
        # print("[DEBUG] Nmap output:\n" + nmap_output)
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap scan timed out")
        return None
    except Exception as e:
        print("[ERROR] Nmap scan failed: {}".format(e))
        return None

    ssl_tls_issues = []
    ssl_issues = load_ssl_issues()

    deprecated_protocols = ssl_issues["Deprecated_Protocols"]
    deprecated_protocol_issues = ["<b>Deprecated Protocols Detected:</b><br>"]

    for deprecated_protocol in deprecated_protocols:
        if deprecated_protocol[0] in nmap_output:
            deprecated_protocol_issues.append('- {0}: <b>{1}</b>'.format(deprecated_protocol[0], deprecated_protocol[1]))

    if len(deprecated_protocol_issues) > 1:
        ssl_tls_issues = deprecated_protocol_issues

    # ###################
    common_weak_ciphers = ssl_issues["Common_Weak_Ciphers"]
    common_weak_cipher_issues = ["<br><b>Common Weak Ciphers:</b><br>"]

    for common_weak_cipher in common_weak_ciphers:
        if common_weak_cipher[0] in nmap_output:
            common_weak_cipher_issues.append(
                '- {0}: '.format(common_weak_cipher[1]) + "<b>Yes</b>")
        else:
            common_weak_cipher_issues.append(
                '- {0}: '.format(common_weak_cipher[1]) + "<b>No</b>")

    if len(common_weak_cipher_issues) > 1:
        ssl_tls_issues = ssl_tls_issues + common_weak_cipher_issues
    # #####################
    known_vulnerabilities = ssl_issues["Known_Vulnerabilities"]
    known_vulnerability_issues = ["<br><b>Known Vulnerabilities:</b><br>"]

    for known_vulnerability in known_vulnerabilities:
        if known_vulnerability[0] in nmap_output:
            known_vulnerability_issues.append(
                '- {0}: '.format(known_vulnerability[1]) + "<b>Yes</b>")
        else:
            known_vulnerability_issues.append(
                '- {0}: '.format(known_vulnerability[1]) + "<b>No</b>")

    if len(known_vulnerability_issues) > 1:
        ssl_tls_issues = ssl_tls_issues + known_vulnerability_issues

    weak_ciphers = ssl_issues["Weak_Ciphers"]
    weak_cipher_issues = ["<br><b>Weak Ciphers:</b><br>"]

    for weak_cipher in weak_ciphers:
        if weak_cipher[0] in nmap_output:
            weak_cipher_issues.append('- <a href="https://ciphersuite.info/cs/{0}">{0}</a>: <b>{1}</b>'
                                      .format(weak_cipher[0], weak_cipher[1]))

    if len(weak_cipher_issues) > 1:
        ssl_tls_issues = ssl_tls_issues + weak_cipher_issues

    if ssl_tls_issues:
        issue_detail = """               
                    The server is configured to support weak SSL/TLS cipher suites, which could allow an attacker to decrypt 
                    or tamper with encrypted traffic through methods such as cryptographic downgrade attacks, brute force,
                    or protocol vulnerabilities.<br><br>
                    During SSL/TLS negotiation with the server, the following weak cipher suites were found to be supported
                    and indication of weak certificate:<br><br>
                    """ + "<br>".join(ssl_tls_issues) + """<br><br>
                    Use of these cipher suites significantly reduces the strength of encryption and may expose sensitive
                    data to interception or modification. SSL Scanner initiated a TLS handshake and observed these weak
                    ciphers in the server's response. This indicates the server is not enforcing modern, secure cipher policies.
                    <br><br><pre>""" + nmap_output + """</pre><br>
                    <b>Issue background</b><br><br>
                    Cipher suites determine how TLS encryption is applied between the client and the server.
                    Older or weak cipher suites use outdated algorithms (e.g., RC4, 3DES, MD5, NULL) that are considered
                    insecure due to vulnerabilities or insufficient key lengths.<br><br>
                    Attackers may exploit these weak ciphers to:<br><br>
                    - Perform downgrade attacks (e.g., forcing use of export-grade or legacy ciphers)<br>
                    - Exploit specific vulnerabilities like SWEET32, FREAK, or LOGJAM<br>
                    - Break confidentiality or integrity of communications<br><br>
                    Modern TLS configurations should use only strong ciphers with forward secrecy and authenticated encryption,
                    such as those based on AES-GCM or ChaCha20-Poly1305.<br><br>
                    <b>Issue remediation</b><br><br>
                    Reconfigure the web server to:<br><br>
                    - Disable all weak, deprecated, or export-grade cipher suites<br>
                    - Enable only secure cipher suites that offer forward secrecy (e.g., ECDHE with AES-GCM)<br>
                    - Prefer TLS 1.2 and 1.3; disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1<br><br>
                    Ensure the final configuration is tested using tools such as:<br><br>
                    - <a href="https://www.ssllabs.com/ssltest/">SSL Labs SSL Test</a><br>
                    - <a href="https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html">nmap --script ssl-enum-ciphers</a><br>
                    - <a href="https://nmap.org/nsedoc/scripts/ssl-cert.html">nmap --script ssl-cert</a><br><br>                    
                    <b>References</b><br><br>
                    - <a href="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html">
                    OWASP: Transport Layer Protection Cheat Sheet</a><br>
                    - <a href="https://www.ssllabs.com/ssltest/">SSL Labs: SSL Server Test</a><br>
                    - <a href="https://ssl-config.mozilla.org/">Mozilla SSL Configuration Generator</a><br>
                    - <a href="https://datatracker.ietf.org/doc/html/rfc7525">RFC 7525: Recommendations for Secure Use of TLS</a><br><br>
                    <b>Vulnerability classifications</b><br><br>
                    - <a href="https://cwe.mitre.org/data/definitions/326.html">CWE-326: Inadequate Encryption Strength</a><br>
                    - <a href="https://cwe.mitre.org/data/definitions/327.html">CWE-327: Use of a Broken or Risky Cryptographic Algorithm</a><br>
                    - <a href="https://capec.mitre.org/data/definitions/242.html">CAPEC-242: Algorithm Downgrade Attack</a><br>
                    - <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183">CVE-2016-2183 (SWEET32)</a><br>
                    - <a href="https://www.first.org/cvss/calculator/3.1">CVSS v3.1 Calculator</a><br>
                    """

        issue = SSLScanIssue(
            httpService,
            request_url,
            [messageInfo],
            "[SecSci SSL Scanner] Weak TLS/SSL Configuration",
            issue_detail,
            "Medium"
        )
        callbacks.addScanIssue(issue)

        print("SSL Scan Completed for " + host + ":" + str(port))


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SecSci SSL/TLS Scanner")
        callbacks.registerHttpListener(self)

        print("[*] SSL/TLS Scanner extension loaded.")

        if not is_nmap_installed():
            print("[ERROR] Unable to locate NMap.")
            print("[INFO] Check NMap installation directory and add to PATH environment variable.")
            return None

        # remote_ssl_issues_url = "https://raw.githubusercontent.com/securityscience/SecSci-SSL-TLS-Scanner/refs/heads/main/ssl_issues.json"
        # fetch_latest_issues(remote_ssl_issues_url)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only act on responses (not requests)
        if messageIsRequest:
            return None

        httpService = messageInfo.getHttpService()
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        request_url = self._helpers.analyzeRequest(messageInfo).getUrl()

        # Skip if not https or the URL is out-of-scope
        if protocol != "https" or not self._callbacks.isInScope(request_url):
            return None

        target = host + ":" + str(port)

        if target not in hosts:
            hosts.append(target)
            # threading.Thread(target=run_nmap_ssl_scan, args=(host, port)).start()
            thread = threading.Thread(target=run_nmap_ssl_scan,
                                      args=(host, port, httpService, request_url, messageInfo, self._callbacks))
            thread.start()

            # print("[INFO] No weak cipher support on %s:%s" % (host, port))


class SSLScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService


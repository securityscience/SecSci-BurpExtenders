# ---------------------------------------
# Sec-Sci NMap SSL Scanner v1.250502 - May 2025
# ---------------------------------------
# Tool:      Sec-Sci NMAP SSL Scanner v1.250502
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender, IHttpListener, IScanIssue
import subprocess
import threading

hosts = []


def run_nmap_ssl_scan(host, port, httpService, request_url, messageInfo, callbacks):
    # nmap_cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host]
    nmap_cmd = ["nmap", "--script", "ssl-*", "-p", str(port), host]

    # print("[INFO] Running Nmap command: {}".format(nmap_cmd))

    try:
        nmap_output = subprocess.check_output(nmap_cmd, stderr=subprocess.STDOUT)
        nmap_output = nmap_output.decode("utf-8")
        # print("[DEBUG] Nmap output:\n" + nmap_output)
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap scan timed out")
        return None
    except Exception as e:
        print("[ERROR] Nmap scan failed: {}".format(e))
        return None

    known_vulnerabilities = [
        "Anonymous cipher suites supported",
        "Low strength cipher suites supported",
        "No support for TLSv1.2 or higher",
        "Insecure renegotiation supported",
        "Client-initiated renegotiation supported",
        "Uses a block cipher in CBC mode with TLS 1.0 or earlier",
        "Certificate uses weak signature algorithm",
        "Key exchange (dh 1024) of lower strength than certificate key"
        "Anonymous cipher suites supported (no authentication)",
        "Low strength cipher suites supported",
        "No support for TLSv1.2 or higher"
    ]

    ssl_issues = [
        ("md5WithRSAEncryption", "Signature algorithm: md5WithRSAEncryption"),  # MD5 signatures
        ("sha1WithRSAEncryption", "Signature algorithm: sha1WithRSAEncryption"),  # SHA-1 deprecated
        ("Self-signed", "Self-signed certificate"),
        ("expired", "Certificate expired"),
        ("size: 1024 bits", "Key size: 1024 bits"),  # Too small
        ("Algorithm: RSA (1024 bits)", "Public Key Algorithm: RSA (1024 bits)"),
        ("not match domain", "Subject CN does not match domain"),
        ("SSLv2", "Deprecated protocol detected: SSLv2"),
        ("SSLv3", "Deprecated protocol detected: SSLv23"),
        ("TLSv1.0", "Deprecated protocol detected: TLSv1.0"),
        ("TLSv1.1", "Deprecated protocol detected: TLSv1.1"),
        ("SWEET32", "64-bit block cipher 3DES vulnerable to SWEET32 attack"),
        ("lower strength", "Key exchange (dh 1024) of lower strength than certificate key"),
        ("BEAST", "Vulnerable to BEAST attack"),
        ("POODLE", "Vulnerable to POODLE attack"),
        ("WITH_RC4", "Weak cipher suites detected: RC4"),  # RC4 is considered insecure / Broken stream cipher (insecure bias).
        ("WITH_NULL", "Weak cipher suites detected: NULL"),  # No encryption at all
        ("_EXP", "Weak cipher suites detected: EXP"),  # Export-grade ciphers (e.g., 40/56-bit)
        ("WITH_DES", "Weak cipher suites detected: DES"),  # Obsolete, easily broken
        ("WITH_3DES", "Weak cipher suites detected: 3DES"),  # Vulnerable to SWEET32 (block size 64-bit)
        ("_MD5", "Weak cipher suites detected: MD5"),  # Weak hashing algorithm
        ("WITH_SEED", "Weak cipher suites detected: SEED"),  # Not widely trusted; included for strictness
        ("WITH_IDEA", "Weak cipher suites detected: IDEA"),  # Not widely trusted; included for strictness
        ("WITH_CAMELLIA", "Weak cipher suites detected: CAMELLIA"),  # Not widely trusted; included for strictness
        ("CBC_SHA", "Weak cipher suites detected: CBC"),  # Can be vulnerable to BEAST/Lucky13 depending on implementation
        ("CRIME", "Weak cipher suites detected: CRIME")
    ]

    issues = []

    for ssl_issue in ssl_issues:
        if ssl_issue[0] in nmap_output:
            issues.append("- " + ssl_issue[1])

    if issues:
        issue_detail = """               
                    The server is configured to support weak SSL/TLS cipher suites, which could allow an attacker to decrypt 
                    or tamper with encrypted traffic through methods such as cryptographic downgrade attacks, brute force,
                    or protocol vulnerabilities.<br><br>
                    During SSL/TLS negotiation with the server, the following weak cipher suites were found to be supported
                    and indication of weak certificate:<br><br>
                    """ + "<br>".join(issues) + """<br><br>
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
                    - nmap --script ssl-enum-ciphers<br><br>
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
            "Weak TLS/SSL Configuration",
            issue_detail,
            "Medium"
        )
        callbacks.addScanIssue(issue)


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sec-Sci NMap SSL Scanner")
        callbacks.registerHttpListener(self)

        print("[*] SSL Weak Cipher Scanner extension loaded.")

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


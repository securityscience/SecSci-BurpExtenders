# ---------------------------------------
# Sec-Sci NMap SSL Scanner v1.250430 - April 2025
# ---------------------------------------
# Tool:      Sec-Sci AutoPT v1.250430
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender, IHttpListener, IScanIssue
import subprocess
import re
hosts = []

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

        if protocol != "https":
            return None

        if host not in hosts:
            hosts.append(host)
            nmap_cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host]
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

            # Indicators of Weak Configurations
            weak_tls_versions = [
                "SSLv2",    # Completely broken, vulnerable to many attacks
                "SSLv3",    # Vulnerable to POODLE
                "TLSv1.0",  # Weak, supports obsolete cipher suites
                "TLSv1.1"   # Deprecated by all major browsers and vendors
            ]

            # Weak Ciphers
            # NULL: No encryption at all.
            # EXP: Export-grade ciphers (e.g., 40/56-bit).
            # DES: Obsolete, easily broken.
            # 3DES: Vulnerable to SWEET32 (block size 64-bit).
            # RC4: Broken stream cipher (insecure bias).
            # MD5: Weak hashing algorithm.
            # CAMELLIA/SEED/IDEA: Not widely trusted; included for strictness.
            # CBC: Can be vulnerable to BEAST/Lucky13 depending on implementation.
            weak_ciphers_regex = r"(NULL|EXP|DES|3DES|RC4_128|MD5|SEED|IDEA|CAMELLIA|CBC|CRIME)[^\\n]* - [CD]"

            known_vulnerabilities = [
                "64-bit block cipher 3DES vulnerable to SWEET32 attack",
                "RC4 is considered insecure",
                "Anonymous cipher suites supported",
                "Low strength cipher suites supported",
                "No support for TLSv1.2 or higher"
                "BEAST attack",
                "POODLE attack",
                "Insecure renegotiation supported",
                "Client-initiated renegotiation supported",
                "Uses a block cipher in CBC mode with TLS 1.0 or earlier",
                "Certificate uses weak signature algorithm",
                "Key exchange (dh 1024) of lower strength than certificate key"
                "Anonymous cipher suites supported (no authentication)",
                "Low strength cipher suites supported",
                "No support for TLSv1.2 or higher"
            ]

            # Weak Certificate
            weak_cert_indicators = [
                "Signature algorithm: md5WithRSAEncryption",   # MD5 signatures
                "Signature algorithm: sha1WithRSAEncryption",  # SHA-1 deprecated
                "Self-signed certificate",
                "Certificate expired",
                "Key size: 1024 bits",                         # Too small
                "Public Key Algorithm: RSA (1024 bits)",
                "Subject CN does not match domain"
            ]

            issues = []

            # Check for Deprecated TLS Versions
            for version in weak_tls_versions:
                if version in nmap_output:
                    issues.append("Deprecated protocol detected: {}".format(version))

            # Check for Weak Ciphers
            weak_ciphers = re.findall(weak_ciphers_regex, nmap_output)
            if weak_ciphers:
                issues.append("Weak cipher suites detected: %s" % ', '.join(set(weak_ciphers)))

            # Check for Known Vulnerabilities
            for known_vulnerability in known_vulnerabilities:
                if known_vulnerability in nmap_output:
                    issues.append("Deprecated protocol detected: {}".format(known_vulnerability))

            # Check for Weak Certificate
            for weak_cert in weak_cert_indicators:
                if weak_cert in nmap_output:
                    issues.append("Deprecated protocol detected: {}".format(weak_cert))

            if issues:
                detail = "<br>".join(issues) + "<br><br><pre>" + nmap_output + "</pre>"
                issue = SSLScanIssue(
                    httpService,
                    self._helpers.analyzeRequest(messageInfo).getUrl(),
                    [messageInfo],
                    "Weak TLS/SSL Configuration",
                    detail,
                    "Medium"
                )
                self._callbacks.addScanIssue(issue)

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


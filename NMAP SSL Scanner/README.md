## 🛡️ NMAP SSL Scanner

This BurpSuite extension integrates `nmap` SSL scanning directly into BurpSuite using Python.
It allows security testers to quickly identify SSL-related vulnerabilities like weak ciphers,
outdated protocols, and certificate issues from within the BurpSuite interface.


## 🚀 Features

- 🔍 Automatically scans HTTPS "In Scope" targets using `nmap --script ssl-*`.
- 📄 Displays results inside BurpSuite Issues.
- 📥 Integrates seamlessly with the Extender API.
- 🔄 Auto-updates SLL issues from the repo.
- 🧪 Works in both Community and Professional editions of BurpSuite.


## 🛠 Prerequisites

Before installing the extension, ensure the following:

| Component       | Required | Notes                                                                                    |
|-----------------|----------|------------------------------------------------------------------------------------------|
| BurpSuite       | ✅        | Community or Professional version                                                        |
| Jython          | ✅        | [Download Jython](https://www.jython.org/download) (e.g., `jython-standalone-2.7.4.jar`) |
| Python (Jython) | ✅        | Must use Python 2.7 syntax                                                               |
| Nmap            | ✅        | Ensure [`nmap`](https://nmap.org/download) is installed and added to PATH                |


## 📥 Installation Steps

### 1. Download the Jython Standalone JAR

1. Go to [https://www.jython.org/download](https://www.jython.org/download)
2. Download the **standalone jar** (e.g. `jython-standalone-2.7.4.jar`)
3. Save the file, e.g., `jython-standalone-2.7.4.jar`, to a known location.

### 2. Enable Python Support in BurpSuite

1. Open **BurpSuite**
2. Navigate to **Extender** → **Options**
3. Scroll to **Python Environment**
4. Click **Select file…**
5. Choose the download file (e.g., `jython-standalone-2.7.4.jar`)

### 3. Add the Extension

1. [Download](https://github.com/securityscience/SecSci-BurpExtenders/raw/refs/heads/main/NMAP%20SSL%20Scanner/NMAP-SSL-Scanner.zip) NMAP SSL Scanner
   - Unzip the download NMAP-SSL-Scanner.zip file
   - MD5 hash: 953d7fcb797a5d1cf6697e2af1b98415
2. Go to **Extender** → **Extensions**
3. Click **Add**
4. Set:
   - **Extension Type**: Python
   - **Extension File**: `nmap_ssl_scanner.py`
5. Click **Next** → then **Finish**

If successful, the extension will show `Loaded` in the table.


## 🔧 Usage Instructions

Once the extension is loaded in BurpSuite:

- Make sure the target host is marked **In Scope** in the **Target** tab.
- Visit an HTTPS page through **Proxy**, **Repeater**, or **Target**.
- The extension will:
  - Detect in-scope HTTPS responses
  - Automatically run:  
    `nmap --script ssl-* -p <port> <host>`
  - Look for known SSL/TLS weaknesses (e.g., SSLv2, SSLv3, RC4, null ciphers, heartbleed etc.) and indication of weak certificate.
  - Report issues directly to the **Scanner → Issues** tab as custom findings


## 🐞 Troubleshooting

| Issue                             | Solution                                                    |
|----------------------------------|-------------------------------------------------------------|
| Extension fails to load          | Make sure you’re using Python 2.7 syntax and Jython is set  |
| Nmap not found                   | Ensure `nmap` is installed and in system's PATH             |
| No scan output shown             | Check **Extender → Output**, or use `print`/`callbacks.printOutput()` |



## 🔐 **SSL/TLS Test Domains**

These subdomains are intentionally configured with specific SSL/TLS issues to aid in testing and validation:

### **🔑 Certificate Issues**

- `https://expired.badssl.com` – Expired certificate
- `https://self-signed.badssl.com` – Self-signed certificate
- `https://untrusted-root.badssl.com` – Untrusted root certificate
- `https://revoked.badssl.com` – Revoked certificate
- `https://pinning-test.badssl.com` – Certificate pinning

### **🔐 Protocol and Cipher Weaknesses**

- `https://tls-v1-0.badssl.com` – TLS 1.0 support
- `https://tls-v1-1.badssl.com` – TLS 1.1 support
- `https://3des.badssl.com` – 3DES cipher support
- `https://rc4.badssl.com` – RC4 cipher support
- `https://cbc.badssl.com` – CBC cipher support
- `https://dh480.badssl.com` – Weak Diffie-Hellman parameters

### **🧪 Other Test Cases**

- `https://mixed.badssl.com` – Mixed content (HTTP and HTTPS)
- `https://sha1-intermediate.badssl.com` – SHA-1 intermediate certificate
- `https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com` – Test for handling long subdomain names


## 📜 License

[GNU GPL 3.0](../LICENSE)


## 🙋 Support

If encounter issues, bugs or want to request features:

- Submit an [Issue](https://github.com/securityscience/SecSci-BurpExtenders/issues)
- Contact: [RnD@security-science.com](mailto:RnD@security-science.com)
- Or [https://www.security-science.com/contact](https://www.security-science.com/contact)


## 🤖 Example Output

📋[ Click here](https://htmlpreview.github.io/?https://github.com/securityscience/SecSci-BurpExtenders/blob/main/NMAP%20SSL%20Scanner/nmap_ssl_scanner_sample_report.html) to view sample exported report from BurpSuite.

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-01 22:34 Eastern Daylight Time
Nmap scan report for 3des.badssl.com (104.154.89.105)
Host is up (0.046s latency).
rDNS record for 104.154.89.105: 105.89.154.104.bc.googleusercontent.com

PORT    STATE SERVICE
443/tcp open  https
| ssl-cert: Subject: commonName=*.badssl.com
| Subject Alternative Name: DNS:*.badssl.com, DNS:badssl.com
| Issuer: commonName=R10/organizationName=Let's Encrypt/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-11T20:02:47
| Not valid after:  2025-06-09T20:02:46
| MD5:   e9b3:deb1:508c:9d1d:e012:4ef1:892c:a97c
|_SHA-1: 0272:a57f:a7a7:3bab:ed17:729a:c018:2c68:b2ae:f80d
|_ssl-date: TLS randomness does not represent time
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (secp256r1) - C
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - D
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|     warnings: 
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Key exchange (dh 1024) of lower strength than certificate key
|   TLSv1.1: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (secp256r1) - C
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - D
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|     warnings: 
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Key exchange (dh 1024) of lower strength than certificate key
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (secp256r1) - C
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - D
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|     warnings: 
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Key exchange (dh 1024) of lower strength than certificate key
|_  least strength: D
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: nginx/1024-bit MODP group with safe prime modulus
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org

Nmap done: 1 IP address (1 host up) scanned in 16.80 seconds
```
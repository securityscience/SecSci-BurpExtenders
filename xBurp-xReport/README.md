## 🔁 xBurp & xReport

**xBurp** and **xReport** are lightweight Python-based BurpSuite extensions designed to automate key scanning and reporting functions. Built specifically for use with [Sec-Sci AutoPT](https://www.security-science.com/sec-sci-autopt) framework, these tools streamline the penetration testing workflow by automating security scan monitoring, exporting report, and BurpSuite shutdown.


## 🔍 Features

### ❎ xBurp
- Monitors BurpSuite's active scan status
- Automatically closes Burp once all scans are complete

### 📝️ xReport
- Exports Burp's scan issues in:
  - HTML format
  - XML format
  - Or both, based on user selection


## ⚙️ Prerequisites

Before installing these extensions, ensure the following:

| Component       | Required | Notes        |
|-----------------|----------|-----------------------------|
| BurpSuite       | ✅        | [Professional version](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install) |
| Jython          | ✅        | [Download Jython](https://www.jython.org/download) (e.g., `jython-standalone-2.7.4.jar`)    |
| Python (Jython) | ✅        | Must use Python 2.7 syntax     |

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

### 3. Load the Extensions into BurpSuite

1. [Download](https://github.com/securityscience/SecSci-BurpExtenders/raw/refs/heads/main/xBurp-xReport/xBurp-xReport.zip) xBurp and xReport
   - Unzip the download `xBurp-xReport.zip` file
   - MD5 hash: `67f74736cc500e1d2bd017bbb22d27fe`
2. Go to **Extender** → **Extensions**
3. Click **Add**
4. Set:
   - **Extension Type**: Python
   - **Extension File**: `xBurp.py`
5. Click **Next** → then **Finish**
6. Repeat step 4 for `xReport.py`


## 🚀 Usage Instructions

### ❎ xBurp

- Load `xBurp.py` into BurpSuite
- Run active scans as usual
- xBurp will monitor the scanning queue and gracefully shuts down Burp once all scans complete

### 📝️ xReport

- Load `xReport.py` into BurpSuite
- Choose export format (HTML, XML, or both)
- Reports will be generated in the configured output directory upon invocation


## 🐞 Troubleshooting

| Issue                             | Solution                                                                                                  |
|----------------------------------|-----------------------------------------------------------------------------------------------------------|
| Extension fails to load          | Make sure you’re using Python 2.7 syntax and Jython is set.                                               |
| Scan not detected by xBurp                  | Verify that the scan was initiated through Burp’s active scanner and that it appears in the scan queue.   |
| No output from xReport            | - Check that issues exist in the target scope.<br/>- Validate write permissions for the output directory. |


## 🧩 Integration with Sec-Sci AutoPT

These extensions are designed to operate seamlessly as part of the [Sec-Sci AutoPT](https://www.security-science.com/sec-sci-autopt) automated penetration testing components.


## 📜 License

[GNU GPL 3.0](../LICENSE)


## 📫 Contact

For issues, bugs, or want to request features:

- Submit an [Issue](https://github.com/securityscience/SecSci-BurpExtenders/issues)
- Contact: [RnD@security-science.com](mailto:RnD@security-science.com)
- Or [https://www.security-science.com/contact](https://www.security-science.com/contact)

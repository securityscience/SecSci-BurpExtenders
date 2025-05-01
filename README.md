## 🛡️ BurpSuite Python-Based Extensions Installation Guide

A guide in installing and running these **Python-based Burp extensions** (also called *extenders*) in **BurpSuite** using **Jython**.


## 🚀 Installation Guide

### 🛠 Prerequisites

- Burp Suite (Community or Professional Edition)
- Python 2.7 (for compatibility with Jython)
- [Jython standalone JAR](https://www.jython.org/download) (e.g., `jython-standalone-2.7.4.jar`)

> ⚠️ Jython only supports Python 2.x syntax. Most Burp APIs are Java-based, and Jython allows Python code to interoperate with them.

### 📥 Step 1: Download Jython

1. Go to [https://www.jython.org/download](https://www.jython.org/downloads)
2. Download the **standalone jar** (e.g. `jython-standalone-2.7.4.jar`)
3. Save the file, e.g., `jython-standalone-2.7.4.jar`, to a known location.

### ⚙ Step 2: Configure Jython on BurpSuite

1. Open BurpSuite
2. Navigate to the **"Extender"** tab → **"Options"**
3. Under **Python Environment**, click **Select file...**
4. Choose the downloaded `jython-standalone-*.jar` file.

### ⚙️ Step 3: Configure Jython in Burp

1. Go to the **"Extender"** tab.
2. Click the **"Options"** sub-tab.
3. Under **"Python Environment"**, click **"Select file..."**.
4. Choose the downloaded `jython-standalone-2.7.3.jar`.

### ➕ Step 4: Add Python-Based Extension

1. Go to the **"Extender"** tab.
2. Click the **"Extensions"** sub-tab.
3. Click **"Add"**.
4. Choose:
   - **Extension Type**: `Python`
   - **Extension File**: Browse to the `.py` extension file
5. Click **"Next"** → then **"Finish"**

BurpSuite will load the extension. If script is valid, it will appear in the list with status `Loaded`.

### 🧪 Step 5: Test the Extension

- Check the **"Output"** and **"Errors"** tabs within **Extender** for logs.
- If extension registers any custom tabs, features, or scanner checks, it must be reflected in the UI or behavior.


## 🧹 Troubleshooting

- **Syntax errors**: Remember that Jython supports **Python 2.7** only.
- **Missing imports**: Jython doesn’t support all native Python libraries, especially ones using C extensions.
- **No logs/output**: Add `print` statements or use `callbacks.printOutput()` for debugging.


## 📚 References

- [Jython Official Website](https://www.jython.org)
- [PortSwigger Extender API Docs](https://portswigger.net/burp/extender/api/)


## ✅ Example Minimal Extension

```python
from burp import IBurpExtender

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # Set extension name shown in Burp
        callbacks.setExtensionName("Python-Based Extension")

        # Simple message to indicate successful loading
        print("Python-Based BurpSuite Extension!")

        # It can also be used to log to the Extender > Output tab
        callbacks.printOutput("Python extension loaded successfully.")
```
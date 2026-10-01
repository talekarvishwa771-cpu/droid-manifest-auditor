# droidguard 🛡️

`droidguard` is a lightweight, zero-dependency Python command-line utility designed to statically analyze `AndroidManifest.xml` files for security misconfigurations, vulnerabilities, and overly permissive access controls.

## Features

- **Zero External Dependencies**: Built entirely using Python's standard library (`xml.etree.ElementTree`, `argparse`, `json`).
- **Cleartext Traffic Detection**: Flags `android:usesCleartextTraffic="true"` which allows insecure HTTP communication.
- **Debuggable Flag Detection**: Detects if `android:debuggable="true"` is left enabled, exposing the app to runtime manipulation.
- **Exported Components Audit**: Scans for Activities, Services, Broadcast Receivers, and Content Providers that are marked `android:exported="true"` (or implicitly exported via intent-filters) without being protected by custom permissions.
- **Dangerous Permission Auditing**: Flags requests for high-risk permissions (e.g., `READ_SMS`, `SYSTEM_ALERT_WINDOW`, `RECORD_AUDIO`) and explains their security implications.
- **Colorized Terminal Output**: Clean, readable, and color-coded CLI interface.
- **JSON Export**: Generate structured JSON reports for integration into CI/CD pipelines or automated vulnerability management systems.

---

## Common Android Manifest Vulnerabilities

### 1. Debuggable Enabled
If `android:debuggable` is set to `true`, anyone with physical access to the device (or via ADB) can attach a debugger to the process, dump memory, extract sensitive application data, and execute arbitrary code.

### 2. Cleartext Traffic Allowed
By default, modern Android versions block unencrypted HTTP traffic. Setting `android:usesCleartextTraffic="true"` bypasses this protection, making the application highly vulnerable to Man-in-the-Middle (MitM) attacks where sensitive API keys, session tokens, and user credentials can be intercepted.

### 3. Unprotected Exported Components
An exported component (`Activity`, `Service`, `Receiver`, or `Provider`) can be launched by any other application installed on the device. If these components do not require a permission to access, malicious apps can exploit them to bypass authentication, steal internal data, or trigger unauthorized actions.

---

## Installation

No installation is required. Simply clone or download `main.py` and run it directly with Python 3.

```bash
chmod +x main.py
```

---

## Usage

### Basic Scan
Run a scan against an `AndroidManifest.xml` file:

```bash
python3 main.py /path/to/AndroidManifest.xml
```

### Save JSON Report
Export the findings to a structured JSON file:

```bash
python3 main.py /path/to/AndroidManifest.xml --json report.json
```

### Disable Color Output
Disable ANSI terminal colors (useful for raw log collection):

```bash
python3 main.py /path/to/AndroidManifest.xml --no-color
```

---

## Exit Codes

- `0`: Scan completed successfully with no `HIGH` severity findings.
- `1`: Scan completed and detected one or more `HIGH` severity findings, or an execution error occurred.

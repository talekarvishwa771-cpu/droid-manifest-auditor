#!/usr/bin/env python3
"""
droidguard - Static AndroidManifest.xml Security Analyzer
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

# Android XML Namespace
NS_ANDROID = "{http://schemas.android.com/apk/res/android}"

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

# Dangerous Permissions List
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Allows reading SMS messages. High risk of privacy leak.",
    "android.permission.RECEIVE_SMS": "Allows intercepting incoming SMS (can bypass 2FA).",
    "android.permission.SEND_SMS": "Allows sending SMS (potential financial fraud via premium numbers).",
    "android.permission.READ_CONTACTS": "Allows reading user contacts database.",
    "android.permission.WRITE_CONTACTS": "Allows modifying user contacts database.",
    "android.permission.ACCESS_FINE_LOCATION": "Allows accessing precise GPS location.",
    "android.permission.ACCESS_COARSE_LOCATION": "Allows accessing approximate network-based location.",
    "android.permission.RECORD_AUDIO": "Allows recording audio from the microphone (potential eavesdropping).",
    "android.permission.CAMERA": "Allows taking photos and recording videos.",
    "android.permission.READ_PHONE_STATE": "Allows access to sensitive device state, including phone number and IMEI.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows drawing overlays over other apps (used in tapjacking/phishing).",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows writing to shared external storage (deprecated but still risky).",
    "android.permission.READ_EXTERNAL_STORAGE": "Allows reading from shared external storage.",
    "android.permission.PROCESS_OUTGOING_CALLS": "Allows intercepting and redirecting outgoing calls.",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Allows starting automatically at boot (often used by persistent malware)."
}

BANNER = f"""{COLOR_CYAN}{COLOR_BOLD}
  _  _             _     _                       _ 
 | || | ___  _ _ (_) __| | __ _  _  _  __ _  _ _ | |
 | __ |/ _ \| '_|| |/ _` |/ _` || || |/ _` || '_||_|
 |_||_|\___/|_|  |_|\__,_|\__, | \_,_|\__,_||_|  (_)
                          |___/                     
             AndroidManifest.xml Security Analyzer
{COLOR_RESET}"""

class ManifestAnalyzer:
    def __init__(self, file_path, use_color=True):
        self.file_path = file_path
        self.use_color = use_color
        self.findings = []
        self.package_name = "Unknown"

    def _color(self, text, color_code):
        if self.use_color:
            return f"{color_code}{text}{COLOR_RESET}"
        return text

    def analyze(self):
        if not os.path.exists(self.file_path):
            print(self._color(f"[-] Error: File not found: {self.file_path}", COLOR_RED), file=sys.stderr)
            sys.exit(1)

        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            print(self._color(f"[-] Error parsing XML: {e}", COLOR_RED), file=sys.stderr)
            sys.exit(1)

        self.package_name = root.attrib.get("package", "Unknown")

        # 1. Check Application-level configurations
        application = root.find("application")
        if application is not None:
            self._check_debuggable(application)
            self._check_cleartext_traffic(application)
            self._check_backup_enabled(application)

        # 2. Check Permissions
        self._check_permissions(root)

        # 3. Check Exported Components
        if application is not None:
            self._check_exported_components(application)

        return self.findings

    def _add_finding(self, severity, category, component, description, recommendation):
        self.findings.append({
            "severity": severity,
            "category": category,
            "component": component,
            "description": description,
            "recommendation": recommendation
        })

    def _check_debuggable(self, application):
        debuggable = application.get(f"{NS_ANDROID}debuggable")
        if debuggable == "true":
            self._add_finding(
                severity="HIGH",
                category="Build Configuration",
                component="Application",
                description="android:debuggable is set to 'true'. This allows attackers to attach debuggers, dump memory, and execute arbitrary code in the context of the app.",
                recommendation="Set android:debuggable to 'false' or remove the attribute entirely before releasing the production build."
            )

    def _check_cleartext_traffic(self, application):
        cleartext = application.get(f"{NS_ANDROID}usesCleartextTraffic")
        # Default is true on API < 28, but explicit true is always a finding
        if cleartext == "true":
            self._add_finding(
                severity="HIGH",
                category="Network Security",
                component="Application",
                description="android:usesCleartextTraffic is set to 'true'. The application allows unencrypted HTTP traffic, exposing sensitive data to Man-in-the-Middle (MitM) attacks.",
                recommendation="Set android:usesCleartextTraffic to 'false' and enforce HTTPS. Use a Network Security Config file for fine-grained control."
            )

    def _check_backup_enabled(self, application):
        allow_backup = application.get(f"{NS_ANDROID}allowBackup")
        # Default is true if not specified
        if allow_backup == "true" or allow_backup is None:
            self._add_finding(
                severity="MEDIUM",
                category="Data Storage",
                component="Application",
                description="android:allowBackup is enabled (either explicitly 'true' or by default). This allows users/attackers to extract application private data via 'adb backup'.",
                recommendation="Set android:allowBackup to 'false' if the application processes or stores sensitive user data."
            )

    def _check_permissions(self, root):
        for uses_permission in root.findall("uses-permission"):
            perm_name = uses_permission.get(f"{NS_ANDROID}name")
            if perm_name in DANGEROUS_PERMISSIONS:
                self._add_finding(
                    severity="MEDIUM",
                    category="Permission",
                    component=perm_name,
                    description=f"Requested dangerous permission: {perm_name}. {DANGEROUS_PERMISSIONS[perm_name]}",
                    recommendation="Ensure this permission is strictly necessary for core functionality. Follow the principle of least privilege."
                )

    def _check_exported_components(self, application):
        # Component tags to analyze
        component_tags = {
            "activity": "Activity",
            "service": "Service",
            "receiver": "Broadcast Receiver",
            "provider": "Content Provider"
        }

        for tag, label in component_tags.items():
            for comp in application.findall(tag):
                comp_name = comp.get(f"{NS_ANDROID}name", "Unnamed Component")
                exported_attr = comp.get(f"{NS_ANDROID}exported")
                has_intent_filter = comp.find("intent-filter") is not None
                permission = comp.get(f"{NS_ANDROID}permission")

                # Determine if exported
                is_exported = False
                if exported_attr == "true":
                    is_exported = True
                elif exported_attr is None and has_intent_filter:
                    # If exported is not defined, but an intent-filter exists, it defaults to true
                    is_exported = True

                if is_exported:
                    # If exported but not protected by a permission
                    if not permission:
                        severity = "HIGH" if tag in ["provider", "service"] else "MEDIUM"
                        self._add_finding(
                            severity=severity,
                            category="Access Control",
                            component=f"{label} ({comp_name})",
                            description=f"The {label} is exported and is not protected by any custom permission. Any external application on the device can launch or interact with it.",
                            recommendation=f"Set android:exported='false' if this component is internal. If it must be public, protect it with a custom android:permission."
                        )
                    else:
                        # Exported but protected by a permission (Info level)
                        self._add_finding(
                            severity="INFO",
                            category="Access Control",
                            component=f"{label} ({comp_name})",
                            description=f"The {label} is exported but protected by permission: '{permission}'.",
                            recommendation="Verify that only trusted applications can obtain this permission."
                        )

    def print_terminal_report():
        pass # Handled in main execution flow


def main():
    parser = argparse.ArgumentParser(
        description="droidguard: Static AndroidManifest.xml Security Analyzer"
    )
    parser.add_argument("manifest", help="Path to the AndroidManifest.xml file to analyze")
    parser.add_argument("--json", help="Path to save the JSON report output")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    use_color = not args.no_color
    analyzer = ManifestAnalyzer(args.manifest, use_color=use_color)

    # Print Banner
    if use_color:
        print(BANNER)
    else:
        print("=== droidguard: AndroidManifest.xml Security Analyzer ===\n")

    print(f"[*] Analyzing: {args.manifest}")
    findings = analyzer.analyze()
    print(f"[*] Target Package: {analyzer.package_name}")
    print(f"[*] Total Findings: {len(findings)}\n")

    # Severity color mapping
    severity_colors = {
        "HIGH": COLOR_RED,
        "MEDIUM": COLOR_YELLOW,
        "INFO": COLOR_CYAN
    }

    # Print Findings
    for idx, finding in enumerate(findings, 1):
        sev = finding["severity"]
        color = severity_colors.get(sev, COLOR_GREEN)
        
        sev_label = analyzer._color(f"[{sev}]", color + COLOR_BOLD)
        print(f"{idx}. {sev_label} {analyzer._color(finding['category'], COLOR_BOLD)}")
        print(f"   Component:      {finding['component']}")
        print(f"   Description:    {finding['description']}")
        print(f"   Recommendation: {finding['recommendation']}")
        print("-" * 80)

    # Save JSON Report if requested
    if args.json:
        report_data = {
            "target_file": args.manifest,
            "package_name": analyzer.package_name,
            "total_findings": len(findings),
            "findings": findings
        }
        try:
            with open(args.json, "w") as f:
                json.dump(report_data, f, indent=4)
            print(analyzer._color(f"[+] JSON report successfully saved to: {args.json}", COLOR_GREEN))
        except Exception as e:
            print(analyzer._color(f"[-] Failed to write JSON report: {e}", COLOR_RED), file=sys.stderr)

    # Exit code based on findings severity
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    if high_count > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()

# customhosts

**customhosts** is a smart, blocklist generator that synchronizes your **NextDNS** activity with your local device. 

It analyzes your logs to generate a consolidated system-level blocklist (`hosts` file). This allows you to block ads, telemetry, and trackers directly on your device **before** the request leaves your network, significantly reducing latency and saving your NextDNS monthly query quota.

## 🚀 Overview

Unlike static blocklists, `customhosts` learns from your specific traffic patterns. It uses statistical analysis and pattern recognition to identify "garbage" subdomains (like generated UUIDs or tracking nodes) and aggressively wildcards them, while automatically protecting the root domains of sites you actually visit.

## ✨ Key Features

* **NextDNS API Integration**: Automatically pulls your blocked domain logs and account allowlists.
* **Deep Suffix Analysis**: Uses intelligent grouping to find the "deepest common parent" for tracking subdomains (e.g., converting `o1.ingest.sentry.io` and `o2.ingest.sentry.io` into `*.ingest.sentry.io`) without blocking the main `sentry.io` site.
* **Dynamic Safety Rails**: Automatically learns your "trusted roots." If you have successfully visited any subdomain of a site (e.g., `www.wikipedia.org`), the script marks `wikipedia.org` as a **Protected Root** and refuses to wildcard block it, preventing accidental breakage.
* **Intelligent Pattern Recognition**: Detects and wildcards generated subdomains containing:
    * UUIDs (e.g., `0160680c-6122-4253...`)
    * Long Hexadecimal strings (e.g., Minerva/A2Z devices)
    * Telemetry keywords (`metrics`, `measure`, `pixel`, etc.)
* **Hybrid Data Sources**: Merges data from:
    * NextDNS API
    * Local `.csv` log exports
    * `whitelist.txt` & `blacklist.txt` (Supports wildcards)
    * Existing System `hosts` files (Windows/Linux)
* **Universal Output**: Generates files for:
    * **App Blocker**: Optimized with wildcards (for Android apps like AdAway/DNS66).
    * **System Hosts**: Expanded standard format for Windows and Linux.

## 🛠️ Requirements

* **Python 3.x**
* **Libraries**: `pandas`, `requests`

* **bash**
* **pip install pandas requests**
  ##⚙️ Configuration

    Edit the Script: Open block.py and update the NEXTDNS_CONFIG dictionary with your details:
    Python

    NEXTDNS_CONFIG = {
        "YOUR_API_KEY": ["profile_id_1", "profile_id_2"],
        "ANOTHER_KEY": ["profile_id_3"]
    }

    Whitelist (whitelist.txt): Create this file to prevent specific domains from ever being blocked. Supports wildcards:
    Plaintext

    *.google.com
    wikipedia.org
    bankofamerica.com

    Blacklist (blacklist.txt): Create this file to force-block domains, overriding safety checks (but not the whitelist):
    Plaintext

    *.annoying-tracker.net
    specific-malware-site.com

🖥️ Usage

Run the script (use sudo if you want it to automatically update /etc/hosts or the Windows hosts file):
Bash

sudo python3 unifiedhosts.py

Output Files

    hosts_app_output.txt: The highly optimized list containing wildcards (e.g., *.ads.example.com). Best for mobile ad-blocking apps.

    hosts_windows_output: Standard hosts format. The script attempts to write this directly to C:\Windows\System32\drivers\etc\hosts. If the file system is read-only (e.g., dual-booting Linux), it saves this file locally for manual copying.

    hosts_linux_output: Standard hosts format for /etc/hosts.

🧠 Logic & Safety

The script follows a strict hierarchy to ensure stability:

    Explicit Whitelist (whitelist.txt + NextDNS Allowlist) WINS.

    Safety Protection: If you visit a site, its root domain is locked.

    Manual Blacklist: Added next.

    ** Wildcards**: Only applied if a domain is NOT protected and exhibits tracking patterns (High Entropy or High Volume).

⚠️ Permission Note for Dual Booters

If you are running this on Linux to update a mounted Windows partition, ensure Windows was fully shut down (not hibernated/Fast Startup). If the partition is read-only, the script will detect this and save the file locally instead of crashing.

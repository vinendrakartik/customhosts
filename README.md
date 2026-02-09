customhosts

Generate your custom block list from your NextDNS blocked domains. Specifically to block on device without reaching NextDNS, saving queries in your monthly quota and improving latency by resolving blocks locally.
🚀 Overview

This tool automatically fetches your activity logs from the NextDNS API and local CSV exports to build a consolidated system-level blocklist. It uses intelligent pattern recognition and statistical analysis to find the "deepest common parent" for tracking subdomains, allowing for aggressive wildcard blocking without breaking the main functionality of trusted sites.
✨ Key Features

    NextDNS API Integration: Automatically downloads your blocked domain logs and account allowlists.

    Deep Suffix Analysis: Smart grouping logic that identifies repeating patterns (e.g., o12345.ingest.sentry.io and o67890.ingest.sentry.io become *.ingest.sentry.io).

    Intelligent Pattern Recognition: Automatically detects and wildcards subdomains containing:

        UUIDs (e.g., 0160680c-6122-4253...)

        Long Hexadecimal IDs (Minerva/A2Z devices)

        Sentry/Telemetry nodes

    Dynamic Safety Rails: Analyzes your "Allowed" traffic to identify user-trusted roots. If you successfully visit any part of a domain, the script marks it as a "Protected Root" and refuses to wildcard it, ensuring sites like Wikipedia, Mozilla, or your banking portals never break.

    Conflict Resolution (WL > BL): Strictly enforces user preference where the whitelist always overrides any automated or manual blacklist.

    Hybrid Data Sources: Merges data from:

        NextDNS API (Logs & Allowlists)

        Local .csv log exports

        whitelist.txt (Supports specific domains and *.wildcards)

        blacklist.txt (Supports specific domains and *.wildcards)

        Existing System hosts files (Windows/Linux)

    Universal Output:

        App Blocker: Optimized with wildcards for tools like AdAway or Personal DNS Filter.

        System Hosts: Standard format for /etc/hosts and Windows drivers.

🛠️ Requirements

    Python 3.x

    pandas

    requests

Bash

pip install pandas requests

⚙️ Setup & Configuration

    API Keys: Open the script and edit the NEXTDNS_CONFIG section with your API key and Profile IDs:
    Python

    NEXTDNS_CONFIG = {
        "your_api_key_1": ["profile_id_a", "profile_id_b"],
        "your_api_key_2": ["profile_id_c"]
    }

    Whitelist (whitelist.txt): Add domains you never want blocked. Use *. for wildcards:
    Plaintext

    *.google.com
    wikipedia.org

    Blacklist (blacklist.txt): Manually force-block specific domains or patterns:
    Plaintext

    *.annoying-tracker.net
    specific-malware-site.com

🖥️ Usage

Run the script with administrative privileges to allow it to update your system hosts files automatically:
Bash

sudo python3 block.py

Output Files

    hosts_app_output.txt: The optimized list using wildcards (Recommended for mobile apps).

    hosts_windows_output: Generated Windows hosts file (fallback if drive is read-only).

    hosts_linux_output: Generated Linux hosts file.

🧠 How the Intelligent Detection Works

The script employs a multi-step analysis to distinguish between "content" domains and "tracking" domains:

    Entropy Analysis: It calculates the mathematical randomness of subdomains. High-entropy strings are flagged as generated tracking IDs.

    Consumption Logic: To prevent over-blocking, the script processes potential wildcards from the deepest subdomain level up to the root. Once a subdomain is covered (consumed) by a wildcard (e.g., *.prod.cloud.adobe.io), it no longer counts toward the threshold for blocking the root (adobe.io).

    Pattern Boosting: High-confidence keywords like ingest, telemetry, measure, and ads lower the cluster threshold, allowing for faster detection of new tracking endpoints.

⚠️ Permission Notes

If you are dual-booting and running this on Linux to update a Windows hosts file on a mounted NTFS partition, ensure Windows was shut down completely (Fast Startup disabled). If the script detects the path is read-only, it will safely save the output in your local directory as hosts_windows_output.

import pandas as pd
import requests
import os
import shutil
import math
import glob
import re
import sys
from datetime import datetime, timedelta
from collections import Counter

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================

# 1. NextDNS Credentials
NEXTDNS_CONFIG = {
    # Replace with your actual ID and profiles
    "YOUR_API_KEY_HERE": ["profile_id_1", "profile_id_2"]
}

# 2. System Paths
WINDOWS_HOSTS_PATH = '/mnt/OS/Windows/System32/drivers/etc/hosts'
LINUX_HOSTS_PATH = '/etc/hosts'
WHITELIST_FILE = 'whitelist.txt'
BLACKLIST_FILE = 'blacklist.txt'

# 3. Output Filenames
OUTPUT_APP = 'hosts_app_output.txt'
OUTPUT_WIN_LOCAL = 'hosts_windows_output'
OUTPUT_LINUX_LOCAL = 'hosts_linux_output'

# 4. Settings
RETENTION_DAYS = 90
CLUSTER_THRESHOLD = 3 

# 5. Protected Roots (NEVER Auto-Wildcard these)
SAFETY_ROOTS = {
    'mozilla.org', 'mozilla.com', 'firefox.com',
    'wikipedia.org', 'wikimedia.org',
    'github.com', 'githubusercontent.com', 'gitlab.com',
    'stackoverflow.com',
    'microsoft.com', 'apple.com', 'google.com', 'android.com',
    'debian.org', 'ubuntu.com', 'fedoraproject.org', 'gnome.org', 'kde.org',
    'pypi.org', 'python.org', 'adobe.com',
    'airtel.in', 'airtel.tv', 'jio.com', 'jiosaavn.com',
    'icicibank.com', 'icici.bank.in', 'hdfcbank.com', 'sbi.co.in',
    'dell.com', 'hp.com', 'lenovo.com', 'intel.com', 'nvidia.com',
    'fbcdn.net', 'facebook.com', 'whatsapp.net', 'instagram.com',
    'blogspot.com', 'wordpress.com', 'tumblr.com',
    'amazon.com', 'amazon.in', 'aws.amazon.com',
    'cloudfront.net', 'qualtrics.com', 'sentry.io', 'adobe.io'
}

# Regex Patterns
RE_UUID = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
RE_HEX_LONG = re.compile(r'^[a-f0-9]{16,}$')
RE_SENTRY_NODE = re.compile(r'^o\d+$')
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ==========================================
# 🛠️ HELPER FUNCTIONS
# ==========================================

def get_nextdns_allowlist(api_key, profile_id):
    url = f"https://api.nextdns.io/profiles/{profile_id}/allowlist"
    headers = {"X-Api-Key": api_key}
    allowed = set()
    print(f"   ⬇️ Allowlist: {profile_id}...", end=" ", flush=True)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if 'data' in data:
            for item in data['data']:
                if item.get('active', True): 
                    domain = item.get('id', '').lower().strip()
                    if domain.startswith("*."): domain = domain[2:]
                    allowed.add(domain)
        print(f"✅ ({len(allowed)})")
    except: print("❌")
    return allowed

def read_list_file(path):
    """Reads whitelist/blacklist and splits Wildcards (*.x) vs Specifics."""
    specific = set()
    wildcards = set()
    if os.path.exists(path):
        print(f"   📖 Reading: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith('#'): continue
                    
                    if line.startswith("*."):
                        wildcards.add(line[2:])
                    else:
                        # FIX: Filter IPs from blacklist file too
                        if not IP_REGEX.match(line):
                            specific.add(line)
        except Exception as e: print(f"   ⚠️ Error: {e}")
    return specific, wildcards

def is_whitelisted(domain, specific_wl, wildcard_wl):
    if domain in specific_wl: return True
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in wildcard_wl: return True
    return False

def download_logs():
    print(f"--- ☁️ Downloading Logs (Last {RETENTION_DAYS} Days) ---")
    temp_files = []
    start_ts = int((datetime.now() - timedelta(days=RETENTION_DAYS)).timestamp() * 1000)
    
    for api_key, profiles in NEXTDNS_CONFIG.items():
        headers = {"X-Api-Key": api_key}
        for pid in profiles:
            url = f"https://api.nextdns.io/profiles/{pid}/logs/download"
            print(f"   ⬇️ {pid}...", end=" ", flush=True)
            try:
                r = requests.get(url, headers=headers, params={"from": start_ts}, stream=True)
                if r.status_code == 400: r = requests.get(url, headers=headers, stream=True)
                r.raise_for_status()
                fn = f"temp_{pid}.csv"
                with open(fn, 'wb') as f:
                    for chunk in r.iter_content(32768): f.write(chunk)
                if os.path.getsize(fn) > 100: 
                    temp_files.append(fn)
                    print("✅")
                else: 
                    os.remove(fn)
                    print("⚠️ (Empty)")
            except: print("❌")
    return temp_files

def write_file(path, fallback, domains, header):
    target = path
    try:
        if os.path.exists(path): writable = os.access(path, os.W_OK)
        else: writable = os.access(os.path.dirname(path) or '.', os.W_OK)
    except: writable = False
    if not writable: target = fallback

    try:
        if target == path and os.path.exists(path):
            try: shutil.copy2(path, path + ".bak")
            except: pass
            
        with open(target, 'w', encoding='utf-8') as f:
            f.write(f"# {header}\n# Generated: {datetime.now()}\n127.0.0.1 localhost\n::1 localhost\n\n")
            for d in sorted(domains): 
                # Final Safety Check for IPs
                if not IP_REGEX.match(d):
                    f.write(f"0.0.0.0 {d}\n")
        print(f"   ✅ Saved: {target}")
    except: print(f"   ❌ Failed to write: {target}")

# ==========================================
# 🚀 CORE LOGIC
# ==========================================

def main():
    print("\n--- 🛡️ Unified Blocklist Generator ---")

    # 1. Load Custom Lists
    wl_specific, wl_wildcards = read_list_file(WHITELIST_FILE)
    bl_specific, bl_wildcards = read_list_file(BLACKLIST_FILE)

    # 2. API Allowlist
    for k, v in NEXTDNS_CONFIG.items():
        for p in v: 
            api_w = get_nextdns_allowlist(k, p)
            for d in api_w:
                if d.startswith("*."): wl_wildcards.add(d[2:])
                else: wl_specific.add(d)

    # 3. Logs
    logs = download_logs()
    logs.extend(glob.glob("*.csv"))
    
    print("\n--- 📊 Processing Data ---")
    csv_blocked = set()
    csv_allowed_log = set()
    
    for f in logs:
        if "temp_" not in f and f not in glob.glob("*.csv"): continue
        try:
            for chunk in pd.read_csv(f, usecols=['domain', 'status'], chunksize=50000):
                chunk['domain'] = chunk['domain'].str.lower().str.strip()
                chunk = chunk.dropna(subset=['domain'])
                # FIX: Filter IPs from logs
                chunk = chunk[~chunk['domain'].str.match(IP_REGEX)]
                
                csv_allowed_log.update(chunk[chunk['status'] != 'blocked']['domain'])
                csv_blocked.update(chunk[chunk['status'] == 'blocked']['domain'])
        except: pass

    # 4. Merge Block Sources (Logs + System Hosts + Blacklist)
    sys_blocked = set()
    for p in [LINUX_HOSTS_PATH, WINDOWS_HOSTS_PATH]:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    for l in f:
                        parts = l.strip().split()
                        # Typical hosts line: 0.0.0.0 domain.com
                        if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                            d = parts[1].lower()
                            if d in ['localhost', 'broadcasthost', 'local']: continue
                            
                            # FIX: STRICT IP FILTER on existing hosts entries
                            if IP_REGEX.match(d): continue
                            
                            sys_blocked.add(d)
            except: pass

    # Combine all potential blocks
    all_candidates = csv_blocked.union(sys_blocked).union(bl_specific)
    
    # 5. Apply Whitelisting (The Gatekeeper)
    final_blocked = set()
    all_wl_specific = wl_specific.union(csv_allowed_log).union(SAFETY_ROOTS)
    
    for d in all_candidates:
        if d in all_wl_specific: continue
        if is_whitelisted(d, set(), wl_wildcards): continue
        final_blocked.add(d)

    print(f"   Unique Blocks: {len(final_blocked)}")
    print(f"   Explicit Whitelist: {len(all_wl_specific)}")

    # 6. Wildcard Detection
    print("\n--- 🤖 Analyzing Patterns ---")
    suffix_counts = Counter()
    domain_map = {} 
    
    for d in final_blocked:
        parts = d.split('.')
        for i in range(len(parts) - 1): 
            suffix = ".".join(parts[i:])
            if suffix == d: continue
            if suffix not in domain_map: domain_map[suffix] = set()
            domain_map[suffix].add(d)
            suffix_counts[suffix] += 1

    auto_wildcards = set()
    covered_domains = set()
    sorted_suffixes = sorted(suffix_counts.keys(), key=lambda x: (x.count('.'), len(x)), reverse=True)
    
    for suffix in sorted_suffixes:
        count = len(domain_map[suffix] - covered_domains)
        if count < CLUSTER_THRESHOLD: continue
        
        # Safety Checks
        if suffix in all_wl_specific or suffix in SAFETY_ROOTS: continue
        if is_whitelisted(suffix, set(), wl_wildcards): continue

        # Heuristics
        is_pattern_match = False
        if any(k in suffix for k in ['ingest', 'measure', 'telemetry', 'metrics', 'netseer', 'ads']): 
            is_pattern_match = True
        
        if not is_pattern_match:
            sample = list(domain_map[suffix])[:5]
            for child in sample:
                prefix = child.replace(f".{suffix}", "")
                if RE_UUID.match(prefix) or RE_HEX_LONG.match(prefix) or RE_SENTRY_NODE.match(prefix):
                    is_pattern_match = True; break
        
        is_safe_root = False
        for root in SAFETY_ROOTS:
            if suffix == root: is_safe_root = True; break
        if is_safe_root: continue

        auto_wildcards.add(suffix)
        covered_domains.update(domain_map[suffix])

    # 7. Merge Manual Blacklist Wildcards
    final_wildcards = auto_wildcards.union(bl_wildcards)

    print(f"   💡 Auto-Wildcards: {len(auto_wildcards)}")
    print(f"   ➕ Manual Wildcards: {len(bl_wildcards)}")

    # 8. Outputs
    print("\n--- 💾 Saving ---")
    
    # A. App Output
    with open(OUTPUT_APP, 'w') as f:
        f.write("# Unified App Blocklist\n# 🤖 Wildcards:\n")
        for w in sorted(final_wildcards): f.write(f"*.{w}\n")
        f.write("\n# 🎯 Specific Domains:\n")
        remaining = [d for d in final_blocked if not any(d.endswith(f".{w}") for w in final_wildcards)]
        for d in sorted(remaining): f.write(f"{d}\n")
    print(f"   ✅ App List Saved")

    # B/C. System Hosts
    write_file(LINUX_HOSTS_PATH, OUTPUT_LINUX_LOCAL, final_blocked, "Unified Linux")
    write_file(WINDOWS_HOSTS_PATH, OUTPUT_WIN_LOCAL, final_blocked, "Unified Windows")

    # Cleanup
    for f in logs:
        if "temp_" in f: 
            try: os.remove(f)
            except: pass
    print("\n✅ Done.")

if __name__ == "__main__":
    main()

import re
import json
import argparse
import time
import os
from collections import defaultdict
from colorama import Fore, init

init(autoreset=True)

# -------------------------------
# SEVERITY + MITRE MAPPING
# -------------------------------
def get_severity_and_mitre(alert_type, count):
    if alert_type == "Brute Force":
        if count >= 20:
            return "CRITICAL", "T1110"
        return "HIGH", "T1110"
    elif alert_type == "Invalid User Scan":
        return "MEDIUM", "T1087"
    elif alert_type == "Scan":
        return "LOW", "T1046"
    return "LOW", "N/A"

def load_config(config_path):
    # Default fallback values to prevent crashes
    defaults = {
        "brute_force_threshold": 5,
        "invalid_user_threshold": 3,
        "top_attackers_limit": 5
    }
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                user_config = json.load(f)
                defaults.update(user_config)
    except (json.JSONDecodeError, KeyError) as e:
        print(Fore.RED + f"[!] Config load error: {e}. Using default thresholds.")
    return defaults

def save_alerts(alerts_list, filename="alerts.json"):
    # Saves alerts on the fly so watch mode actually logs them
    with open(filename, "w") as f:
        json.dump(alerts_list, f, indent=4)

# -------------------------------
# MAIN FUNCTION
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Threat Detect CLI Tool")
    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("--watch", action="store_true", help="Real-time monitoring")

    args = parser.parse_args()

    # Load config safely
    config = load_config(args.config)
    BRUTE_THRESHOLD = config.get("brute_force_threshold", 5)
    INVALID_THRESHOLD = config.get("invalid_user_threshold", 3)
    TOP_LIMIT = config.get("top_attackers_limit", 5)

    print(Fore.CYAN + """
=====================================
      Threat Detect CLI Tool
=====================================
""")
    print(Fore.CYAN + "[+] Running analysis...\n")

    failed_attempts = defaultdict(int)
    invalid_users = defaultdict(int)

    alerted_brute = set()
    alerted_invalid = set()
    master_alerts_log = []

    # -------------------------------
    # LOG READER (No Amnesia)
    # -------------------------------
    def read_log(file, watch_mode):
        # Reads the whole file first, then waits for new lines if in watch mode
        while True:
            line = file.readline()
            if not line:
                if watch_mode:
                    time.sleep(0.5)
                    continue
                else:
                    break
            yield line

    # Proper IPv4 Regex
    ip_regex = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

    try:
        with open(args.file, "r") as file:
            if args.watch:
                print(Fore.CYAN + "[+] Real-time monitoring enabled (reading history first)...\n")

            for line in read_log(file, args.watch):
                
                # Prevent infinite memory leaks by capping tracking dicts
                if len(failed_attempts) > 10000:
                    failed_attempts.clear()
                    alerted_brute.clear()
                if len(invalid_users) > 10000:
                    invalid_users.clear()
                    alerted_invalid.clear()

                # -------------------------------
                # BRUTE FORCE
                # -------------------------------
                if any(x in line for x in ["Failed password", "authentication failures", "maximum authentication attempts exceeded"]):
                    ip_match = ip_regex.search(line)
                    if ip_match:
                        ip = ip_match.group()
                        failed_attempts[ip] += 1

                        if ip not in alerted_brute and failed_attempts[ip] >= BRUTE_THRESHOLD:
                            severity, mitre = get_severity_and_mitre("Brute Force", failed_attempts[ip])
                            print(Fore.RED + f"[BRUTE FORCE][{severity}][{mitre}] {ip} → {failed_attempts[ip]}")
                            alerted_brute.add(ip)
                            
                            master_alerts_log.append({
                                "ip": ip, "type": "Brute Force", "count": failed_attempts[ip],
                                "severity": severity, "mitre": mitre
                            })
                            save_alerts(master_alerts_log)

                # -------------------------------
                # INVALID USER
                # -------------------------------
                if "Invalid user" in line:
                    ip_match = ip_regex.search(line)
                    if ip_match:
                        ip = ip_match.group()
                        invalid_users[ip] += 1

                        if ip not in alerted_invalid and invalid_users[ip] >= INVALID_THRESHOLD:
                            severity, mitre = get_severity_and_mitre("Invalid User Scan", invalid_users[ip])
                            print(Fore.YELLOW + f"[USER SCAN][{severity}][{mitre}] {ip} → {invalid_users[ip]}")
                            alerted_invalid.add(ip)

                            master_alerts_log.append({
                                "ip": ip, "type": "Invalid User Scan", "count": invalid_users[ip],
                                "severity": severity, "mitre": mitre
                            })
                            save_alerts(master_alerts_log)

                # -------------------------------
                # SCAN DETECTION
                # -------------------------------
                if "Did not receive identification string" in line or "Bad protocol version" in line:
                    severity, mitre = get_severity_and_mitre("Scan", 1)
                    print(Fore.BLUE + f"[SCAN][{severity}][{mitre}] Suspicious connection attempt")

    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] File not found: {args.file}")
        return
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Execution stopped by user.")

    # -------------------------------
    # SUMMARY (non-watch mode)
    # -------------------------------
    if not args.watch:
        print("\n=== TOP ATTACKERS ===\n")
        combined = defaultdict(int)
        for ip in failed_attempts:
            combined[ip] += failed_attempts[ip]
        for ip in invalid_users:
            combined[ip] += invalid_users[ip]

        top_ips = sorted(combined.items(), key=lambda x: x[1], reverse=True)

        for ip, count in top_ips[:TOP_LIMIT]:
            print(f"{ip} → {count} events")

        print("\n=== HIGH RISK IPS ===\n")
        for ip in failed_attempts:
            if ip in invalid_users:
                print(Fore.MAGENTA + f"[HIGH RISK] {ip}")

        print(Fore.GREEN + "\n[+] Done. Alerts saved to alerts.json\n")


# -------------------------------
# ENTRY POINT
# -------------------------------
if __name__ == "__main__":
    main()
import csv
from datetime import timedelta

class Filter:
    def __init__(self, file_path):
        """Storage for filtering decisions"""
        self.file_path = file_path
        self.ip_activities = {}  # Dictionary with IPs as keys and a list of their activities
        self.filtered = []  # List of logs that passed filtering
        self.brute_force_attackers = set()  # Set of IPs with excessive JWT failures
        self.aggregated_attackers = {}  # Dictionary with filtered logs grouped by IP
        self.multi_step_attacks = {}  # Store detected attack sequences

    def filter_logs(self):
        """Processes and filters logs"""

        low_priority_violations = {"JWT Validation Failed", "Invalid Token", "Session Expired"}
        jwt_threshold = 10  # Flag brute-force attackers if JWT failures ≥ 10

        with open(self.file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)  # Read CSV as a dictionary

            for row in reader:
                ip = row["externalIp"]
                attack_type = row["violationCategory"]

                # Track attack history for the IP
                if ip not in self.ip_activities:
                    self.ip_activities[ip] = []
                self.ip_activities[ip].append(attack_type)

                # Apply filtering rules
                jwt_failures = self.ip_activities[ip].count("JWT Validation Failed")
                # Keep log if:
                if len(set(self.ip_activities[ip])) > 1:
                    # IP has multiple different attack types
                    self.filtered.append(row)
                elif jwt_failures >= jwt_threshold:
                    # Excessive JWT failures from the same IP (Possible brute-force attack)
                    self.brute_force_attackers.add(ip)  # Track brute-force attackers
                elif attack_type not in low_priority_violations:
                    # Attack is NOT in low-priority list, so we keep it
                    self.filtered.append(row)

    def aggregate_by_ip(self):
        """Aggregates incidents by IP"""
        for log in self.filtered:
            ip = log["externalIp"]  # extract IP from log

            if ip not in self.aggregated_attackers:
                self.aggregated_attackers[ip] = []
            self.aggregated_attackers[ip].append(log)

        return self.aggregated_attackers

    def detect_attack_sequences(self):
        """Detects multistep attack sequences"""

        # attack categories
        RECON_ATTACKS = {"Path Traversal", "Information Leakage"}
        EXPLOIT_ATTACKS = {"Injections", "Cross Site Scripting"}
        BRUTE_FORCE_ATTACKS = {"JWT Validation Failed", "Authentication & Authorization"}
        ACCOUNT_TAKEOVER = {"Access Control"}

        # Sort logs per IP by timestamp
        for ip, logs in self.aggregated_attackers.items():
            logs.sort(key=lambda x: x["receivedTimeFormatted"])

            found_recon = False
            found_exploit = False
            found_brute_force = False
            found_account_takeover = False
            recon_time = None
            brute_force_time = None

            # Iterate over logs to detect sequences
            for log in logs:
                attack_type = log["violationCategory"]
                timestamp = log["receivedTimeFormatted"]

                # Detect Reconnaissance - Exploitation
                if attack_type in RECON_ATTACKS:
                    found_recon = True
                    recon_time = timestamp  # Store the first reconnaissance timestamp

                if attack_type in EXPLOIT_ATTACKS and found_recon:
                    # Ensure exploitation happens AFTER reconnaissance
                    if recon_time and timestamp > recon_time:
                        self.multi_step_attacks[ip] = "Reconnaissance - Exploitation"

                # Detect Brute-Force - Account Takeover
                if attack_type in BRUTE_FORCE_ATTACKS:
                    found_brute_force = True
                    brute_force_time = timestamp  # Store brute-force attempt time

                if attack_type in ACCOUNT_TAKEOVER and found_brute_force:
                    # Ensure account takeover happens AFTER brute-force
                    if brute_force_time and timestamp > brute_force_time:
                        self.multi_step_attacks[ip] = "Brute-Force - Account Takeover"

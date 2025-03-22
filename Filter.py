import csv


class Filter:
    def __init__(self, file_path):
        """Initialize the filter with log file path and prepare data structures"""
        self.file_path = file_path
        self.ip_activities = {}  # Dictionary with IPs as keys and a list of their activities
        self.filtered = []  # List of logs that passed filtering
        self.jwt_brute_force_attackers = set()  # Set of IPs with excessive JWT failures
        self.access_control_brute_force_attackers = set()  # Set of IPs with excessive Access Control violations
        self.aggregated_attackers = {}  # Dictionary with filtered logs grouped by IP
        self.multi_step_attacks = {}  # Store detected attack sequences

    def create_ip_activities(self):
        """Creates a dictionary of activities per IP"""
        with open(self.file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)  # Read CSV as a dictionary

            for row in reader:
                ip = row["externalIp"]
                attack_type = row["violationCategory"]

                # Track attack history for the IP
                if ip not in self.ip_activities:
                    self.ip_activities[ip] = []
                self.ip_activities[ip].append(attack_type)

    def filter_logs(self):
        """Applies filtering rules to logs"""
        low_priority_violations = {"JWT Validation Failed", "Invalid Token", "Session Expired", "Access Control"}
        sensitive_endpoints = {"/.env", "/config.json", "/.git/config", "/admin/", "/api/keys"}  # Sensitive paths
        jwt_threshold = 10  # Flag brute-force attackers if JWT failures ≥ 10
        access_control_threshold = 5  # Flag brute-force attackers if access control violations ≥ 5

        with open(self.file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)

            for row in reader:
                ip = row["externalIp"]
                attack_type = row["violationCategory"]
                request_uri = row["uri"]

                attack_list = self.ip_activities[ip]
                jwt_failures = attack_list.count("JWT Validation Failed")
                access_control_failures = attack_list.count("Access Control")

                # Keep log if:
                if attack_type == "Access Control":
                    if access_control_failures >= access_control_threshold:
                        # Excessive Access Control violations from the same IP (Possible brute-force attack)
                        self.access_control_brute_force_attackers.add(ip)
                    if request_uri in sensitive_endpoints:
                        # Access Control violations on sensitive endpoints
                        self.filtered.append(row)

                if len(set(self.ip_activities[ip])) > 1:
                    # IP has multiple different attack types
                    self.filtered.append(row)
                elif jwt_failures >= jwt_threshold:
                    # Excessive JWT failures from the same IP (Possible brute-force attack)
                    self.jwt_brute_force_attackers.add(ip)  # Track JWT brute-force attackers
                elif attack_type not in low_priority_violations:
                    # Attack is NOT in low-priority list, so we keep it
                    self.filtered.append(row)

    def aggregate_by_ip(self):
        """Groups all filtered logs by IP"""
        for log in self.filtered:
            ip = log["externalIp"]  # extract IP from log

            if ip not in self.aggregated_attackers:
                self.aggregated_attackers[ip] = []
            self.aggregated_attackers[ip].append(log)

    def detect_attack_sequences(self):
        """Detects multistep attack sequences"""

        # attack categories
        RECON_ATTACKS = {"Path Traversal", "Information Leakage"}
        EXPLOIT_ATTACKS = {"Injections", "Cross Site Scripting"}
        BRUTE_FORCE_ATTACKS = {"JWT Validation Failed", "Authentication & Authorization"}
        ACCOUNT_TAKEOVER = {"Access Control"}

        for ip, logs in self.aggregated_attackers.items():
            logs.sort(key=lambda x: x["receivedTimeFormatted"])  # Sort logs per IP by timestamp

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

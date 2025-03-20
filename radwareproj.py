from Filter import Filter  # Import the Filter class
from LLMProcessor import LLMProcessor  # Import the LLMProcessor class
import time


# Define the path to the WAF log file
file_path = r"C:\Users\nadav\RadwareProject\security_events.csv"
# API key for authentication
api_key = "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"

# Initialize the Filter class to process and filter WAF logs
filter_obj = Filter(file_path)
# Initialize the LLMProcessor class to generate attack summaries
llm = LLMProcessor(api_key)

# Run the filtering process
# After this, filter_obj's filtered, aggregated_attackers and multi_step_attacks are good
filter_obj.create_ip_activities()
filter_obj.filter_logs()
filter_obj.aggregate_by_ip()
filter_obj.detect_attack_sequences()

# Generate attack summaries using LLM
print("Generated Attack Summaries:")
for ip, logs in filter_obj.aggregated_attackers.items():
    detected_sequence_status = filter_obj.multi_step_attacks.get(ip, "None")  # Retrieves the detected multistep attack sequence for the IP
    jwt_brute_force_status = ip in filter_obj.jwt_brute_force_attackers
    access_control_brute_force_status = ip in filter_obj.access_control_brute_force_attackers

    success = False  # Make sure we got a response of the IP
    delay = 5

    # Make sure we don't skip attacker if we didn't get a response
    while not success:
        # Send logs + detected attack sequences to LLM
        attack_summary_json = llm.attack_summary(ip, logs, detected_sequence_status, jwt_brute_force_status, access_control_brute_force_status)

        if attack_summary_json:
            print(f"1️⃣ Attacker IP: {attack_summary_json.get('attacker_ip', 'N/A')}")
            print(f"2️⃣ Attack Summary: {attack_summary_json.get('attack_summary', 'N/A')}")
            print(f"3️⃣ Attack Types: [{', '.join(attack_summary_json.get('attack_types', []))}]")
            print(f"4️⃣ Suggested Mitigation: {attack_summary_json.get('suggested_mitigation', 'N/A')}")
            print()
            success = True
        else:
            print(f"\n⚠️ No valid response for attacker: {ip}")
            print()

        # time.sleep(delay)

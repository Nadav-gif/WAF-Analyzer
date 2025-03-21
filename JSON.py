import json
import os
from Filter import Filter  # Import the Filter class
from LLMProcessor import LLMProcessor  # Import the LLMProcessor class

# Retrieve file path from environment variable
file_path = os.getenv("FILE_PATH")
if not file_path:
    raise ValueError("File path is missing! Make sure to provide --file_path when running the script.")

# Retrieve API key from environment variable
api_key = os.getenv("API_KEY")
if not api_key:
    raise ValueError("API Key is missing! Make sure to provide --api_key when running the script.")

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
for ip, logs in filter_obj.aggregated_attackers.items():
    detected_sequence_status = filter_obj.multi_step_attacks.get(ip, "None")  # Retrieves the detected multistep attack sequence for the IP
    jwt_brute_force_status = ip in filter_obj.jwt_brute_force_attackers
    access_control_brute_force_status = ip in filter_obj.access_control_brute_force_attackers

    success = False  # Make sure we got a response of the IP

    # Make sure we don't skip attacker if we didn't get a response
    while not success:
        # Send logs and additional info to LLM
        attack_summary_json = llm.attack_summary(ip, logs, detected_sequence_status, jwt_brute_force_status, access_control_brute_force_status)

        if attack_summary_json:
            # Ensure attack_types is formatted as a single-line list
            attack_summary_json["attack_types"] = "[" + ", ".join(attack_summary_json.get("attack_types", [])) + "]"

            print(json.dumps(attack_summary_json, indent=0))
            success = True
        else:
            print(f"\nNo valid response for attacker: {ip}")

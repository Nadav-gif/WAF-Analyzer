import json

from filter import Filter  # Import the Filter class
from llm_processor import LLMProcessor  # Import the LLMProcessor class


def json_runner(api_key, file_path):
    # Initialize classes
    filter_obj = Filter(file_path)
    llm = LLMProcessor(api_key)

    # Run the filtering and aggregation process
    filter_obj.create_ip_activities()
    filter_obj.filter_logs()
    filter_obj.aggregate_by_ip()
    filter_obj.detect_attack_sequences()

    # Generate attack summaries using LLM
    for ip, logs in filter_obj.aggregated_attackers.items():
        detected_sequence_status = filter_obj.multi_step_attacks.get(ip, "None")  # Retrieves the detected multistep attack sequence for the IP
        jwt_brute_force_status = ip in filter_obj.jwt_brute_force_attackers
        access_control_brute_force_status = ip in filter_obj.access_control_brute_force_attackers

        success = False  # Make sure we got a response for the IP

        # Make sure we don't skip attackers if we didn't get a response
        while not success:
            # Send logs and additional info to LLM
            attack_summary_json = llm.attack_summary(
                ip,
                logs,
                detected_sequence_status,
                jwt_brute_force_status,
                access_control_brute_force_status
            )

            if attack_summary_json:
                # Ensure attack_types is formatted as a single-line list
                attack_summary_json["attack_types"] = "[" + ", ".join(attack_summary_json.get("attack_types", [])) + "]"

                print(json.dumps(attack_summary_json, indent=0))
                success = True
            else:
                print(f"\nNo valid response for attacker: {ip}")

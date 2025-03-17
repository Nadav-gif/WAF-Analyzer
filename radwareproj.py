from Filter import Filter  # Import the Filter class
from LLMProcessor import LLMProcessor  # Import the LLMProcessor class
import json
import time

# Define the path to the WAF log file
file_path = r"C:\Users\nadav\RadwareProject\security_events.csv"
api_key = "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"

# Create an instance of the Filter class
filter_obj = Filter(file_path)
llm = LLMProcessor(api_key)

# Run the filtering process
filter_obj.filter_logs()
filter_obj.aggregate_by_ip()
filter_obj.detect_attack_sequences()

# Generate attack summaries using LLM
print("\n📊 **Generated Attack Summaries:**")
for ip, logs in filter_obj.aggregated_attackers.items():
    detected_sequence = filter_obj.multi_step_attacks.get(ip, "None")  # Default to "None" if no attack sequence found

    # 🔹 Send logs + detected attack sequences to LLM
    attack_summary_list = llm.attack_summary(ip, logs, detected_sequence)

    if attack_summary_list:
        print(f"1️⃣ Attacker IP: {attack_summary_list[0]}")
        print(f"2️⃣ Attack Summary: {attack_summary_list[1]}")
        print(f"3️⃣ Attack Types: {attack_summary_list[2]}")
        print(f"4️⃣ Suggested Mitigation: {attack_summary_list[3]}")
        print()
    else:
        print(f"\n⚠️ No valid response for attacker: {ip}")
        print()

    time.sleep(5)

import requests
import json


class LLMProcessor:
    def __init__(self, api_key):  # Understand this fields !!!
        """Initialize LLMProcessor with Hugging Face API key"""
        self.api_key = api_key
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "mixtral-8x7b-32768"

    def attack_summary(self, attacker_ip, attacker_logs, detected_sequence):
        """Send data to LLM and returns a list with appropriate fields"""

        # Extract relevant fields from logs and shorten details
        processed_logs = [
            f"- [{log['receivedTimeFormatted']}] {log['violationCategory']} attack on {log.get('uri', 'N/A')} (Severity: {log.get('severity', 'Unknown')})"
            for log in attacker_logs
        ]

        # Define the structured prompt
        prompt = f"""
                You are an AI security analyst. Analyze the following security logs and detected attack sequences. 
                Summarize the attack behavior and suggest mitigations.

                ⚠️ IMPORTANT: Return your response as **four distinct bullet points** ONLY.
                Do not include introductions, explanations, or formatting other than:

                - Attacker IP: {attacker_ip}
                - Attack Summary: <attack_summary>
                - Attack Types: <list of attack types>
                - Suggested Mitigation: <security recommendations>

                Logs:
                {json.dumps(processed_logs, indent=2)}  # Send only the last 5 logs for better accuracy

                Detected Sequence (if any): {detected_sequence}
                """

        # Prepare API request
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system",
                 "content": "You are an AI cybersecurity expert. Analyze security logs and generate structured attack reports."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.5
        }

        response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)

        """
        # Debugging print statements
        print(f"🔹 Sending request to LLM for {attacker_ip}...")
        print(f"🔹 API Response Code: {response.status_code}")
        print(f"🔹 Response Text: {response.text}")
        """

        # Parse response
        if response.status_code == 200:
            try:
                response_json = response.json()
                raw_text = response_json["choices"][0]["message"]["content"].strip()
                return self.parse_text_response(raw_text)
            except (KeyError, json.JSONDecodeError):
                print(f"❌ Error: Invalid LLM response format for {attacker_ip}")
                return None
        else:
            print(f"❌ API Error: {response.status_code}")
            return None

    def parse_text_response(self, response_text):
        """Extracts structured attack details from LLM response"""
        lines = response_text.split("\n")
        extracted_info = {"attacker_ip": "", "attack_summary": "", "attack_types": "", "suggested_mitigation": ""}

        for line in lines:
            if line.startswith("- Attacker IP:"):
                extracted_info["attacker_ip"] = line.replace("- Attacker IP:", "").strip()
            elif line.startswith("- Attack Summary:"):
                extracted_info["attack_summary"] = line.replace("- Attack Summary:", "").strip()
            elif line.startswith("- Attack Types:"):
                extracted_info["attack_types"] = line.replace("- Attack Types:", "").strip()
            elif line.startswith("- Suggested Mitigation:"):
                extracted_info["suggested_mitigation"] = line.replace("- Suggested Mitigation:", "").strip()

        return list(extracted_info.values())  # Convert dict values to a list

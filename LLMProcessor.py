import requests
import json


class LLMProcessor:
    def __init__(self, api_key):  # Understand this fields !!!
        """Initialize LLMProcessor with Hugging Face API key"""
        self.api_key = api_key  # Authenticate requests to Groq API
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"  # Endpoint URL where requests are sent
        self.model = "llama-3.1-8b-instant"  # The LLM model groq should use for text generation

    def attack_summary(self, attacker_ip, attacker_logs, detected_sequence_status, jwt_brute_force_status, access_control_brute_force_status):
        """Send data to LLM and handle the response"""

        # Extract relevant fields from logs and shorten details
        # {
        #     "receivedTimeFormatted": "13/03/2025 9:41",
        #     "violationCategory": "SQL Injection",
        #     "uri": "/login",
        #     "severity": "High"
        # }
        processed_logs = [
            f"Description:{log['description']}, Received time:{log['receivedTimeFormatted']}, Violation Type:{log['violationType']} Target URI: {log.get('uri', 'N/A')}"
            for log in attacker_logs
        ]

        # Define the structured prompt
        prompt = f"""
        You are a cybersecurity expert analyzing security logs from a Web Application Firewall (WAF). 
        Your task is to **identify attack patterns, assess severity correctly, and suggest practical mitigations**.

        ### **Response Format**
        Return the response **ONLY** as structured JSON:
        {{
            "attacker_ip": {attacker_ip} - this parameter is the IP! don't use whats in the log!,
            "attack_summary": "<Brief attack description, including attack patterns and intent>",
            "attack_types": ["<Attack Type 1>", "<Attack Type 2>"] - Take the value of Violation Type!,
            "suggested_mitigation": "<Specific, actionable security recommendations>"
        }}

        ### **Important Rules**
        1) **Responses MUST be in JSON format and only in JSON format!!**
            - You MUST return ONLY JSON formats.
            - NEVER start your answer with the term 'json'.
            - Never go down a line. The answer MUST be in a single line.
            - inside the "content" field, the content MUST be json.
        
        2) **Assess severity accurately:**  
           - **DO NOT** label every attack as "high severity."  
           - Only classify as **high severity** if it **poses an immediate risk** (e.g., SQL Injection, Remote Code Execution, credential brute force).  

        3) **Always include a suggested mitigation:**  
           - If **SQL Injection**, Recommend **prepared statements, input validation**.  
           - If **Brute Force**, suggest **rate limiting, MFA, CAPTCHA**.  
           - If **Reconnaissance - Exploitation**, Mention **monitoring & proactive blocking**.
           - If no obvious mitigation exists, suggest **general best security practices** (e.g., logging, monitoring, access controls).

        4) **Emphasize detected multi-step attack sequences:**  
           - If a **multi-step attack sequence is detected**, mention how it **progressed** (e.g., Reconnaissance - Exploitation).
           - If **brute-force activity was detected**, mention it and how it led to other attacks.  
           - If **no sequence is detected** and **no brute-force is detected**, do not mention it.
           
        5) the "attack_types" should be in a **LIST BRACKETS []**!!! for example [URL Access Violation, Predictable Resource Location]
        
        6) **VERY IMPORTANT!** If you detect **multiple waves of attacks per IP** (e.g., one group of events in a short time span, and another group in a different time),
           **consider it in your answer** and analyze the different attack waves separately.

        7) **Detect attack escalation (VERY IMPORTANT!!!)**  
           - If an attacker **progresses from simple to advanced techniques** over time, mention it in the attack summary.  
           - Example: If an attacker **starts with login brute-force and later moves to SQL Injection**, describe it as **an escalation in attack methods**.  
           - If no escalation is detected, do not mention it.

        ### **Security Logs to Analyze**
        {json.dumps(processed_logs, indent=2)}

        ### **Detected Multi-Step Attack Sequence**: {detected_sequence_status}
        ### **Detected JWT Brute-Force Attack**: {jwt_brute_force_status}
        ### **Detected JWT Brute-Force Attack**: {access_control_brute_force_status}
        
        IMPORTANT: **Always include the attacker IP exactly as provided in the response.**
        
        EXAMPLE OF A GOOD OUTPUT:
        {{
            "attacker_ip": "192.168.1.100",
            "attack_summary": "Over a 24-hour period, this attacker targeted login and search endpoints with multiple SQL Injection attempts to bypass authentication, followed by XSS payloads designed to exfiltrate session cookies.", 
            "attack_types": ["SQL Injection", "Cross-Site Scripting (XSS)"], 
            "suggested_mitigation": "Enforce input validation, use parameterized queries, and sanitize inputs to mitigate SQL Injection and XSS vulnerabilities."
        }}
        """

        # Prepare API request
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        # Data sent to the API
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an AI cybersecurity expert. Analyze security logs and generate structured attack reports. Your answers MUST be in JSON format"},  # System message - instructs the LLM on how to behave
                {"role": "user", "content": prompt}  # User message - the actual prompt
            ],
            "temperature": 0.5,  # Controls how random or deterministic the AI’s response is
        }

        response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)  # Sends an HTTP POST request to the Groq API to get an LLM-generated response
        # Parse response
        if response.status_code == 200:
            response_json = response.json()  # Converts the response to a python dictionary
            llm_content = response_json["choices"][0]["message"]["content"].strip()  # Extracts the actual text response from the API
            structured_response = json.loads(llm_content)
            return structured_response  # Return structured JSON directly
        else:
            print(f"API Error: {response.status_code}")
            return None

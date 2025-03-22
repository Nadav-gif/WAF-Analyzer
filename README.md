# WAF Log Analyzer with LLM-Powered Attack Summarization

The project analyzes Web Application Firewall (WAF) logs to detect and summarize malicious activity, using rule-based filtering and a Large Language Model (LLM). It includes an interactive Streamlit dashboard and also supports JSON output for automation and integration.

---

## Features
- **Log Filtering**: Removes noise and detects significant attacks like brute-force, access control violations, and multi-step sequences.
- **LLM Integration (Groq API)**: Generates natural-language summaries of attacker behavior.
- **Multi-step Attack Detection**: Identifies patterns like Reconnaissance → Exploitation or Brute-force → Account Takeover.
- **Escalation Detection**: Spots attackers who evolve their techniques over time.
- **Interactive Streamlit Dashboard**: Visualize attacker stories and filter by IP.
- **JSON Mode**: Console-based mode for structured output in automation-friendly format.

---

## Requirements
- Python 3.10+
- `requests`, `pandas`, `matplotlib`, `streamlit`
- Groq API key (free tier available)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## How to Run

### Option 1: Streamlit UI Mode
```bash
python proj.py --output UI --api_key YOUR_GROQ_API_KEY --file_path path/to/security_events.csv
```
![image](https://github.com/user-attachments/assets/8ac94162-4302-4913-8e9f-d8df915fd499)


### Option 2: JSON Output Mode
```bash
python proj.py --output JSON --api_key YOUR_GROQ_API_KEY --file_path path/to/security_events.csv
```
![image](https://github.com/user-attachments/assets/f08eea90-16f1-4148-bcc6-19c90f956b9f)

---

## 📁 Project Structure
```
.
├── proj.py               # Entry point for both UI/JSON modes
├── JSON.py               # JSON output logic
├── UI.py                 # Streamlit-based UI
├── Filter.py             # Log filtering & detection logic
├── LLMProcessor.py       # Handles interaction with Groq API
├── requirements.txt
└── security_events.csv   # Sample input (user-provided)
```

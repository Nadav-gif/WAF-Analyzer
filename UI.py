import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from Filter import Filter
from LLMProcessor import LLMProcessor
from datetime import datetime

# Streamlit UI
st.title("🔍 Attacker Analysis Dashboard")

# Initialize session state for attack summaries
if "attack_summaries" not in st.session_state:
    st.session_state.attack_summaries = {}

# Show loading animation while data is being processed
with st.spinner("Processing logs and generating attack summaries..."):
    # Only run filtering and LLM analysis if we haven't done it before
    if not st.session_state.attack_summaries:
        # Constants
        file_path = r"C:\Users\nadav\RadwareProject\security_events.csv"  # Your WAF log file path
        api_key = "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"

        # Initialize the Filter and LLMProcessor classes
        filter_obj = Filter(file_path)
        llm = LLMProcessor(api_key)

        # Run filtering and aggregation processes
        filter_obj.create_ip_activities()
        filter_obj.filter_logs()
        filter_obj.aggregate_by_ip()
        filter_obj.detect_attack_sequences()

        # Generate attack summaries using LLM
        attack_summaries = {}
        for ip, logs in filter_obj.aggregated_attackers.items():
            detected_sequence_status = filter_obj.multi_step_attacks.get(ip, "None")
            jwt_brute_force_status = ip in filter_obj.jwt_brute_force_attackers
            access_control_brute_force_status = ip in filter_obj.access_control_brute_force_attackers

            # Ensure we get a valid response from the LLM
            success = False
            while not success:
                attack_summary_json = llm.attack_summary(ip, logs, detected_sequence_status, jwt_brute_force_status, access_control_brute_force_status)
                if attack_summary_json:
                    attack_summaries[ip] = {"attacker_ip": ip, **attack_summary_json}
                    success = True

            # Save results in session state
            st.session_state.attack_summaries = attack_summaries

# Convert stored attack summaries to a DataFrame
df = pd.DataFrame.from_dict(st.session_state.attack_summaries, orient="index")
# If 'attacker_ip' exists as a column and as the index, drop the column version
if "attacker_ip" in df.columns:
    df = df.drop(columns=["attacker_ip"])

# Ensure attacker_ip is set as the index for better presentation
df.index.name = "attacker_ip"

# IP Filter
selected_ip = st.selectbox("Filter by Attacker IP:", ["All"] + list(st.session_state.attack_summaries.keys()))

# Display filtered results
if selected_ip == "All":
    st.write(df)
else:
    st.write(df.loc[selected_ip])

# Attack frequency graph
st.subheader("📈 Attack Frequency Over Time")

# Extract timestamps from filtered logs
attack_timestamps = [log["receivedTimeFormatted"] for log in filter_obj.filtered]
print(type(attack_timestamps[0]))

# Convert timestamps to datetime objects
attack_timestamps = [
    ts if isinstance(ts, datetime) else datetime.strptime(ts, "%d/%m/%Y %H:%M")
    for ts in attack_timestamps
]


# Create DataFrame for time-based aggregation
df_time = pd.DataFrame({"timestamp": attack_timestamps})

# Set time interval for binning
df_time["time_bin"] = df_time["timestamp"].dt.floor("10T")  # 10 minute intervals

# Count number of attacks per time bin
attack_counts = df_time.groupby("time_bin").size().reset_index(name="attack_count")

# Plot the attack frequency graph
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(attack_counts["time_bin"], attack_counts["attack_count"], marker="o", linestyle="-", color="b")

# Format X-axis to display only the time (HH:MM)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))  # Show every 20 minutes

# Labels and title
ax.set_xlabel("Time")
ax.set_ylabel("Number of Attacks")
ax.set_title("Attack Frequency Over Time")
ax.grid(True)

# Rotate x-axis labels for readability
plt.xticks(rotation=45)

# Display the graph in Streamlit
st.pyplot(fig)

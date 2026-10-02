import pandas as pd


# ============================================================
# LOAD DATA
# ============================================================

PROFILES_FILE = "cyberguard_organisation_profiles.csv"
EVENTS_FILE = "cyberguard_login_events.csv"


profiles = pd.read_csv(PROFILES_FILE)
events = pd.read_csv(EVENTS_FILE)


# ============================================================
# DETECTOR 1: MULTIPLE FAILED LOGIN ATTEMPTS
# ============================================================

def detect_multiple_failed_logins(events, threshold=5):
    """
    Detect users with multiple failed login attempts.

    A user is flagged when they have at least `threshold`
    failed login attempts within a short time window.
    """

    events["timestamp"] = pd.to_datetime(events["timestamp"])

    failed = events[events["login_status"] == "failed"].copy()

    detections = []

    for user_id, user_events in failed.groupby("user_id"):

        user_events = user_events.sort_values("timestamp")

        timestamps = user_events["timestamp"].tolist()

        for i in range(len(timestamps)):

            window_start = timestamps[i]
            window_end = window_start + pd.Timedelta(minutes=10)

            attempts = user_events[
                (user_events["timestamp"] >= window_start) &
                (user_events["timestamp"] <= window_end)
            ]

            if len(attempts) >= threshold:

                detections.append({
                    "user_id": user_id,
                    "threat": "Multiple Failed Login Attempts",
                    "failed_attempts": len(attempts),
                    "first_attempt": attempts["timestamp"].min(),
                    "last_attempt": attempts["timestamp"].max(),
                    "risk": "HIGH"
                })

                break

    return pd.DataFrame(detections)


# ============================================================
# RUN DETECTOR
# ============================================================

detections = detect_multiple_failed_logins(events)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n========================================")
print(" CYBERGUARD ACCOUNT TAKEOVER DETECTOR")
print("========================================")

print("\nDetector: Multiple Failed Login Attempts")

if detections.empty:

    print("\nNo suspicious activity detected.")

else:

    print(f"\nUsers detected: {len(detections)}\n")

    for _, detection in detections.iterrows():

        print("----------------------------------------")
        print(f"User ID:          {detection['user_id']}")
        print(f"Threat:           {detection['threat']}")
        print(f"Failed Attempts:  {detection['failed_attempts']}")
        print(f"First Attempt:    {detection['first_attempt']}")
        print(f"Last Attempt:     {detection['last_attempt']}")
        print(f"Risk Level:       {detection['risk']}")

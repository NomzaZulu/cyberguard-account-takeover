import pandas as pd


# ============================================================
# CYBERGUARD
# CREDENTIAL THEFT & ACCOUNT TAKEOVER DETECTION ENGINE
# ============================================================


# ============================================================
# DETECTOR 1: MULTIPLE FAILED LOGIN ATTEMPTS
# ============================================================

def detect_multiple_failed_logins(events, threshold=5):
    """
    Detect multiple failed login attempts against the same user
    within a 10-minute window.
    """

    events = events.copy()

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    failed = events[
        events["login_status"].astype(str).str.lower() == "failed"
    ].copy()

    detections = []

    for user_id, user_events in failed.groupby("user_id"):

        user_events = user_events.sort_values("timestamp")

        timestamps = user_events["timestamp"].tolist()

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            window_end = (
                window_start
                + pd.Timedelta(minutes=10)
            )

            attempts = user_events[
                (user_events["timestamp"] >= window_start)
                &
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
# DETECTOR 2: PASSWORD SPRAYING
# ============================================================

def detect_password_spraying(
    events,
    min_users=5,
    window_minutes=10
):
    """
    Detect password spraying.

    Same IP attempts authentication against multiple
    different accounts within a short period.
    """

    events = events.copy()

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    failed = events[
        events["login_status"].astype(str).str.lower() == "failed"
    ].copy()

    detections = []

    for ip_address, ip_events in failed.groupby("ip_address"):

        ip_events = ip_events.sort_values("timestamp")

        timestamps = ip_events["timestamp"].tolist()

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            window_end = (
                window_start
                + pd.Timedelta(
                    minutes=window_minutes
                )
            )

            window_events = ip_events[
                (ip_events["timestamp"] >= window_start)
                &
                (ip_events["timestamp"] <= window_end)
            ]

            unique_users = (
                window_events["user_id"].nunique()
            )

            if unique_users >= min_users:

                detections.append({
                    "ip_address": ip_address,
                    "threat": "Password Spraying",
                    "targeted_users": unique_users,
                    "first_attempt": window_events["timestamp"].min(),
                    "last_attempt": window_events["timestamp"].max(),
                    "risk": "HIGH"
                })

                break

    return pd.DataFrame(detections)


# ============================================================
# DETECTOR 3: UNUSUAL LOGIN LOCATION
# ============================================================

def detect_unusual_locations(events, profiles):
    """
    Detect login events from locations that are not listed
    as normal locations for that specific user.
    """

    events = events.copy()
    profiles = profiles.copy()

    profile_locations = {}

    for _, profile in profiles.iterrows():

        normal_locations = [
            location.strip()
            for location in str(
                profile["normal_locations"]
            ).split("|")
            if location.strip()
        ]

        profile_locations[
            profile["user_id"]
        ] = normal_locations

    detections = []

    for _, event in events.iterrows():

        user_id = event["user_id"]

        location = str(
            event["location"]
        ).strip()

        normal_locations = profile_locations.get(
            user_id,
            []
        )

        if location not in normal_locations:

            detections.append({
                "event_id": event["event_id"],
                "user_id": user_id,
                "threat": "Unusual Login Location",
                "detected_location": location,
                "normal_locations": ", ".join(
                    normal_locations
                ),
                "timestamp": event["timestamp"],
                "risk": "MEDIUM"
            })

    return pd.DataFrame(detections)


# ============================================================
# DETECTOR 4: UNKNOWN / NEW DEVICE
# ============================================================

def detect_unknown_devices(events, profiles):
    """
    Detect login events from devices that are not listed
    as known devices for that specific user.
    """

    events = events.copy()
    profiles = profiles.copy()

    # --------------------------------------------------------
    # Build user -> known devices lookup
    # --------------------------------------------------------

    profile_devices = {}

    for _, profile in profiles.iterrows():

        known_devices = [
            device.strip()
            for device in str(
                profile["known_devices"]
            ).split("|")
            if device.strip()
        ]

        profile_devices[
            profile["user_id"]
        ] = known_devices

    detections = []

    # --------------------------------------------------------
    # Check every login event
    # --------------------------------------------------------

    for _, event in events.iterrows():

        user_id = event["user_id"]

        device = str(
            event["device"]
        ).strip()

        known_devices = profile_devices.get(
            user_id,
            []
        )

        # Device is not recognised for this user
        if device not in known_devices:

            detections.append({
                "event_id": event["event_id"],
                "user_id": user_id,
                "threat": "Unknown / New Device",
                "detected_device": device,
                "known_devices": ", ".join(
                    known_devices
                ),
                "timestamp": event["timestamp"],
                "risk": "MEDIUM"
            })

    return pd.DataFrame(detections)


# ============================================================
# OPTIONAL DIRECT ENGINE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print(" CYBERGUARD ACCOUNT TAKEOVER DETECTION ENGINE")
    print("=" * 60)

    try:

        profiles = pd.read_csv(
            "cyberguard_organisation_profiles.csv"
        )

        events = pd.read_csv(
            "cyberguard_login_events.csv"
        )

        print(
            f"\nLoaded {len(profiles)} organisation users."
        )

        print(
            f"Loaded {len(events)} login events."
        )

        # ----------------------------------------------------
        # Detector 1
        # ----------------------------------------------------

        result_1 = detect_multiple_failed_logins(
            events
        )

        print(
            "\n[1] Multiple Failed Login Attempts"
        )

        print(
            f"Detections: {len(result_1)}"
        )

        # ----------------------------------------------------
        # Detector 2
        # ----------------------------------------------------

        result_2 = detect_password_spraying(
            events
        )

        print(
            "\n[2] Password Spraying"
        )

        print(
            f"Detections: {len(result_2)}"
        )

        # ----------------------------------------------------
        # Detector 3
        # ----------------------------------------------------

        result_3 = detect_unusual_locations(
            events,
            profiles
        )

        print(
            "\n[3] Unusual Login Location"
        )

        print(
            f"Detections: {len(result_3)}"
        )

        # ----------------------------------------------------
        # Detector 4
        # ----------------------------------------------------

        result_4 = detect_unknown_devices(
            events,
            profiles
        )

        print(
            "\n[4] Unknown / New Device"
        )

        print(
            f"Detections: {len(result_4)}"
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print(" DETECTION SUMMARY")
        print("=" * 60)

        print(
            f"\nMultiple failed logins : {len(result_1)}"
        )

        print(
            f"Password spraying      : {len(result_2)}"
        )

        print(
            f"Unusual locations      : {len(result_3)}"
        )

        print(
            f"Unknown devices        : {len(result_4)}"
        )

        print("\nEngine test completed.")

    except FileNotFoundError as e:

        print(
            "\nERROR: Required CSV file was not found."
        )

        print(
            f"Missing file: {e.filename}"
        )

    except Exception as e:

        print(
            f"\nERROR: {str(e)}"
        )

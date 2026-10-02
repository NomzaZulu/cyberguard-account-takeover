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
    within a short time window.

    Default:
        5 or more failed attempts within 10 minutes.
    """

    events = events.copy()

    # Make sure timestamps are datetime objects
    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    # Keep only failed login attempts
    failed = events[
        events["login_status"].str.lower() == "failed"
    ].copy()

    detections = []

    # Analyse each user separately
    for user_id, user_events in failed.groupby("user_id"):

        user_events = user_events.sort_values(
            "timestamp"
        )

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
                    "first_attempt": attempts[
                        "timestamp"
                    ].min(),
                    "last_attempt": attempts[
                        "timestamp"
                    ].max(),
                    "risk": "HIGH"
                })

                # One detection per user is enough
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
    Detect possible password spraying.

    Password spraying occurs when the same source/IP
    attempts authentication against multiple different
    user accounts within a short period.
    """

    events = events.copy()

    # Convert timestamps
    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    # Only failed login attempts
    failed = events[
        events["login_status"].str.lower() == "failed"
    ].copy()

    detections = []

    # Analyse each source IP
    for ip_address, ip_events in failed.groupby(
        "ip_address"
    ):

        ip_events = ip_events.sort_values(
            "timestamp"
        )

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

            # Number of different accounts targeted
            unique_users = (
                window_events["user_id"]
                .nunique()
            )

            if unique_users >= min_users:

                detections.append({
                    "ip_address": ip_address,
                    "threat": "Password Spraying",
                    "targeted_users": unique_users,
                    "first_attempt": window_events[
                        "timestamp"
                    ].min(),
                    "last_attempt": window_events[
                        "timestamp"
                    ].max(),
                    "risk": "HIGH"
                })

                # One detection per IP is enough
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

    # --------------------------------------------------------
    # Build user -> normal locations lookup
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Check every login event
    # --------------------------------------------------------

    for _, event in events.iterrows():

        user_id = event["user_id"]

        location = str(
            event["location"]
        ).strip()

        normal_locations = profile_locations.get(
            user_id,
            []
        )

        # Location not recognised for this user
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
# OPTIONAL: TEST ENGINE DIRECTLY
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print(" CYBERGUARD ACCOUNT TAKEOVER DETECTION ENGINE")
    print("=" * 60)

    try:

        # ----------------------------------------------------
        # Load datasets
        # ----------------------------------------------------

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

        print(
            "\n[1] Multiple Failed Login Attempts"
        )

        failed_login_results = (
            detect_multiple_failed_logins(events)
        )

        print(
            f"Detections: {len(failed_login_results)}"
        )


        # ----------------------------------------------------
        # Detector 2
        # ----------------------------------------------------

        print(
            "\n[2] Password Spraying"
        )

        password_spraying_results = (
            detect_password_spraying(events)
        )

        print(
            f"Detections: {len(password_spraying_results)}"
        )


        # ----------------------------------------------------
        # Detector 3
        # ----------------------------------------------------

        print(
            "\n[3] Unusual Login Location"
        )

        unusual_location_results = (
            detect_unusual_locations(
                events,
                profiles
            )
        )

        print(
            f"Detections: {len(unusual_location_results)}"
        )


        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print(" DETECTION SUMMARY")
        print("=" * 60)

        print(
            f"\nMultiple failed logins : "
            f"{len(failed_login_results)}"
        )

        print(
            f"Password spraying      : "
            f"{len(password_spraying_results)}"
        )

        print(
            f"Unusual locations      : "
            f"{len(unusual_location_results)}"
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

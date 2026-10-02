import pandas as pd


# ============================================================
# CYBERGUARD RISK ENGINE
# Credential Theft & Account Takeover Detection
# ============================================================


# ============================================================
# RISK WEIGHTS
# ============================================================

RISK_WEIGHTS = {
    "Multiple Failed Login Attempts": 25,
    "Password Spraying": 30,
    "Unusual Login Location": 15,
    "Unknown / New Device": 15,
    "Suspicious Session Activity": 20,
    "Sudden Account Behaviour Change": 20
}


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


# ============================================================
# BUILD RISK REPORT
# ============================================================

def build_risk_report(
    failed_login_results,
    password_spraying_results,
    unusual_location_results,
    unknown_device_results,
    suspicious_session_results,
    behaviour_change_results
):

    detections = []


    # ========================================================
    # DETECTOR 1
    # Multiple Failed Login Attempts
    # ========================================================

    if not failed_login_results.empty:

        for _, row in failed_login_results.iterrows():

            detections.append({

                "user_id": row["user_id"],

                "threat":
                    "Multiple Failed Login Attempts",

                "weight":
                    RISK_WEIGHTS[
                        "Multiple Failed Login Attempts"
                    ],

                "reason": (
                    f'{row["failed_attempts"]} '
                    f'failed login attempts detected'
                )
            })


    # ========================================================
    # DETECTOR 2
    # Password Spraying
    # ========================================================

    if not password_spraying_results.empty:

        for _, row in password_spraying_results.iterrows():

            # ------------------------------------------------
            # Get the actual targeted users
            # ------------------------------------------------

            targeted_users = str(
                row["targeted_user_ids"]
            ).split(", ")


            # ------------------------------------------------
            # Create individual evidence for every
            # targeted account
            # ------------------------------------------------

            for user_id in targeted_users:

                detections.append({

                    "user_id": user_id,

                    "threat":
                        "Password Spraying",

                    "weight":
                        RISK_WEIGHTS[
                            "Password Spraying"
                        ],

                    "reason": (
                        f'Password spraying detected '
                        f'from IP {row["ip_address"]}; '
                        f'{row["targeted_users"]} accounts '
                        f'targeted within the detection window'
                    )
                })


    # ========================================================
    # DETECTOR 3
    # Unusual Login Location
    # ========================================================

    if not unusual_location_results.empty:

        for _, row in unusual_location_results.iterrows():

            detections.append({

                "user_id":
                    row["user_id"],

                "threat":
                    "Unusual Login Location",

                "weight":
                    RISK_WEIGHTS[
                        "Unusual Login Location"
                    ],

                "reason": (
                    f'Login detected from '
                    f'{row["detected_location"]}'
                )
            })


    # ========================================================
    # DETECTOR 4
    # Unknown / New Device
    # ========================================================

    if not unknown_device_results.empty:

        for _, row in unknown_device_results.iterrows():

            detections.append({

                "user_id":
                    row["user_id"],

                "threat":
                    "Unknown / New Device",

                "weight":
                    RISK_WEIGHTS[
                        "Unknown / New Device"
                    ],

                "reason": (
                    f'Previously unknown device: '
                    f'{row["detected_device"]}'
                )
            })


    # ========================================================
    # DETECTOR 5
    # Suspicious Session Activity
    # ========================================================

    if not suspicious_session_results.empty:

        for _, row in suspicious_session_results.iterrows():

            detections.append({

                "user_id":
                    row["user_id"],

                "threat":
                    "Suspicious Session Activity",

                "weight":
                    RISK_WEIGHTS[
                        "Suspicious Session Activity"
                    ],

                "reason": (
                    f'Suspicious session action: '
                    f'{row["session_action"]}'
                )
            })


    # ========================================================
    # DETECTOR 6
    # Sudden Account Behaviour Change
    # ========================================================

    if not behaviour_change_results.empty:

        for _, row in behaviour_change_results.iterrows():

            detections.append({

                "user_id":
                    row["user_id"],

                "threat":
                    "Sudden Account Behaviour Change",

                "weight":
                    RISK_WEIGHTS[
                        "Sudden Account Behaviour Change"
                    ],

                "reason":
                    row["indicators"]
            })


    # ========================================================
    # NO DETECTIONS
    # ========================================================

    if not detections:

        return (
            pd.DataFrame(),
            pd.DataFrame()
        )


    # ========================================================
    # CREATE DETECTION DATAFRAME
    # ========================================================

    detections_df = pd.DataFrame(
        detections
    )


    # ========================================================
    # AGGREGATE RISK BY USER
    # ========================================================

    risk_rows = []


    for user_id, user_events in detections_df.groupby(
        "user_id"
    ):

        # ----------------------------------------------------
        # Unique detector types
        # ----------------------------------------------------

        unique_threats = (
            user_events["threat"]
            .drop_duplicates()
            .tolist()
        )


        # ----------------------------------------------------
        # Calculate raw score
        # ----------------------------------------------------

        raw_score = int(
            user_events["weight"].sum()
        )


        # ----------------------------------------------------
        # Limit score to 100
        # ----------------------------------------------------

        score = min(
            raw_score,
            100
        )


        # ----------------------------------------------------
        # Determine risk level
        # ----------------------------------------------------

        risk_level = get_risk_level(
            score
        )


        # ----------------------------------------------------
        # Collect evidence
        # ----------------------------------------------------

        reasons = (
            user_events["reason"]
            .drop_duplicates()
            .tolist()
        )


        # ----------------------------------------------------
        # Create final user report
        # ----------------------------------------------------

        risk_rows.append({

            "user_id":
                user_id,

            "risk_score":
                score,

            "risk_level":
                risk_level,

            "detector_count":
                len(unique_threats),

            "detectors_triggered":
                ", ".join(unique_threats),

            "reasons":
                " | ".join(reasons)
        })


    # ========================================================
    # CREATE FINAL RISK REPORT
    # ========================================================

    risk_report = pd.DataFrame(
        risk_rows
    )


    # ========================================================
    # HIGHEST RISK FIRST
    # ========================================================

    risk_report = (
        risk_report
        .sort_values(
            by="risk_score",
            ascending=False
        )
        .reset_index(
            drop=True
        )
    )


    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return (
        risk_report,
        detections_df
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "CYBERGUARD RISK ENGINE"
    )

    print("=" * 60)


    print(
        "\nRisk weights:"
    )


    for threat, weight in RISK_WEIGHTS.items():

        print(
            f"{threat}: {weight}"
        )


    print(
        "\nRisk engine loaded successfully."
    )

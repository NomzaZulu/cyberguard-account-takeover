import pandas as pd


# ============================================================
# CYBERGUARD RISK ENGINE
# Credential Theft & Account Takeover Detection
# ============================================================


# ============================================================
# BASE SCORES
# ============================================================

BASE_SCORES = {
    "Multiple Failed Login Attempts": 20,
    "Password Spraying": 25,
    "Unusual Login Location": 15,
    "Unknown / New Device": 15,
    "Suspicious Session Activity": 20,
    "Sudden Account Behaviour Change": 15
}


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 35:
        return "MEDIUM"

    else:
        return "LOW"


# ============================================================
# EVIDENCE STRENGTH
# ============================================================

def get_evidence_bonus(
    threat,
    row
):

    bonus = 0

    # --------------------------------------------------------
    # Multiple failed logins
    # --------------------------------------------------------

    if threat == "Multiple Failed Login Attempts":

        failed_attempts = int(
            row.get(
                "failed_attempts",
                0
            )
        )

        unique_ips = int(
            row.get(
                "unique_source_ips",
                1
            )
        )

        if failed_attempts >= 8:
            bonus += 5

        if failed_attempts >= 12:
            bonus += 5

        if unique_ips >= 2:
            bonus += 5

    # --------------------------------------------------------
    # Password spraying
    # --------------------------------------------------------

    elif threat == "Password Spraying":

        targeted_users = int(
            row.get(
                "targeted_users",
                0
            )
        )

        if targeted_users >= 8:
            bonus += 5

        if targeted_users >= 12:
            bonus += 5

    # --------------------------------------------------------
    # Unusual location
    # --------------------------------------------------------

    elif threat == "Unusual Login Location":

        baseline_source = str(
            row.get(
                "baseline_source",
                ""
            )
        )

        if baseline_source == "Historical user activity":
            bonus += 3

    # --------------------------------------------------------
    # New device
    # --------------------------------------------------------

    elif threat == "Unknown / New Device":

        baseline_source = str(
            row.get(
                "baseline_source",
                ""
            )
        )

        if baseline_source == "Historical user activity":
            bonus += 3

    # --------------------------------------------------------
    # Suspicious session
    # --------------------------------------------------------

    elif threat == "Suspicious Session Activity":

        privileged_actions = int(
            row.get(
                "privileged_actions",
                0
            )
        )

        rapid_actions = int(
            row.get(
                "rapid_actions",
                0
            )
        )

        if privileged_actions > 0:
            bonus += 10

        if rapid_actions >= 2:
            bonus += 5

    # --------------------------------------------------------
    # Behaviour change
    # --------------------------------------------------------

    elif threat == "Sudden Account Behaviour Change":

        indicators = str(
            row.get(
                "indicators",
                ""
            )
        )

        indicator_count = len(
            [
                item
                for item in indicators.split(";")
                if item.strip()
            ]
        )

        if indicator_count >= 2:
            bonus += 5

        if indicator_count >= 3:
            bonus += 5

    return bonus


# ============================================================
# BUILD DETECTION RECORD
# ============================================================

def add_detection(
    detections,
    user_id,
    threat,
    row,
    reason
):

    base_score = BASE_SCORES.get(
        threat,
        0
    )

    bonus = get_evidence_bonus(
        threat,
        row
    )

    contribution = min(
        base_score + bonus,
        40
    )

    detections.append({

        "user_id":
            str(user_id),

        "threat":
            threat,

        "base_score":
            base_score,

        "evidence_bonus":
            bonus,

        "score_contribution":
            contribution,

        "reason":
            reason
    })


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
    # MULTIPLE FAILED LOGIN ATTEMPTS
    # ========================================================

    if (
        failed_login_results is not None
        and
        not failed_login_results.empty
    ):

        for _, row in (
            failed_login_results.iterrows()
        ):

            user_id = row[
                "user_id"
            ]

            failed_attempts = row.get(
                "failed_attempts",
                0
            )

            source_ips = row.get(
                "source_ips",
                ""
            )

            reason = (
                f"{failed_attempts} failed "
                f"login attempts detected"
            )

            if str(source_ips).strip():

                reason += (
                    f" from source IP(s): "
                    f"{source_ips}"
                )

            add_detection(
                detections,
                user_id,
                "Multiple Failed Login Attempts",
                row,
                reason
            )


    # ========================================================
    # DETECTOR 2
    # PASSWORD SPRAYING
    # ========================================================

    if (
        password_spraying_results is not None
        and
        not password_spraying_results.empty
    ):

        for _, row in (
            password_spraying_results.iterrows()
        ):

            # ------------------------------------------------
            # New detector format:
            # one row can contain targeted users
            # ------------------------------------------------

            if "targeted_user_ids" in row.index:

                targeted_users = [
                    user.strip()
                    for user in str(
                        row["targeted_user_ids"]
                    ).split(",")
                    if user.strip()
                ]

            # ------------------------------------------------
            # Alternative format:
            # already one user per row
            # ------------------------------------------------

            elif "user_id" in row.index:

                targeted_users = [
                    str(
                        row["user_id"]
                    )
                ]

            else:

                targeted_users = []


            for user_id in targeted_users:

                targeted_count = row.get(
                    "targeted_users",
                    len(targeted_users)
                )

                reason = (
                    f"Password spraying detected "
                    f"from IP "
                    f"{row.get('ip_address', 'unknown')}; "
                    f"{targeted_count} accounts targeted"
                )

                add_detection(
                    detections,
                    user_id,
                    "Password Spraying",
                    row,
                    reason
                )


    # ========================================================
    # DETECTOR 3
    # UNUSUAL LOGIN LOCATION
    # ========================================================

    if (
        unusual_location_results is not None
        and
        not unusual_location_results.empty
    ):

        for _, row in (
            unusual_location_results.iterrows()
        ):

            user_id = row[
                "user_id"
            ]

            location = row.get(
                "detected_location",
                "unknown"
            )

            baseline_source = row.get(
                "baseline_source",
                ""
            )

            reason = (
                f"Login detected from "
                f"{location}"
            )

            if str(
                baseline_source
            ).strip():

                reason += (
                    f"; baseline based on "
                    f"{baseline_source}"
                )

            add_detection(
                detections,
                user_id,
                "Unusual Login Location",
                row,
                reason
            )


    # ========================================================
    # DETECTOR 4
    # UNKNOWN / NEW DEVICE
    # ========================================================

    if (
        unknown_device_results is not None
        and
        not unknown_device_results.empty
    ):

        for _, row in (
            unknown_device_results.iterrows()
        ):

            user_id = row[
                "user_id"
            ]

            device = row.get(
                "detected_device",
                "unknown"
            )

            baseline_source = row.get(
                "baseline_source",
                ""
            )

            reason = (
                f"Previously unseen device: "
                f"{device}"
            )

            if str(
                baseline_source
            ).strip():

                reason += (
                    f"; baseline based on "
                    f"{baseline_source}"
                )

            add_detection(
                detections,
                user_id,
                "Unknown / New Device",
                row,
                reason
            )


    # ========================================================
    # DETECTOR 5
    # SUSPICIOUS SESSION ACTIVITY
    # ========================================================

    if (
        suspicious_session_results is not None
        and
        not suspicious_session_results.empty
    ):

        for _, row in (
            suspicious_session_results.iterrows()
        ):

            user_id = row[
                "user_id"
            ]

            reasons = row.get(
                "reasons",
                ""
            )

            if not str(
                reasons
            ).strip():

                reasons = (
                    f"Suspicious session activity: "
                    f"{row.get('session_action', '')}"
                )

            add_detection(
                detections,
                user_id,
                "Suspicious Session Activity",
                row,
                str(reasons)
            )


    # ========================================================
    # DETECTOR 6
    # SUDDEN ACCOUNT BEHAVIOUR CHANGE
    # ========================================================

    if (
        behaviour_change_results is not None
        and
        not behaviour_change_results.empty
    ):

        for _, row in (
            behaviour_change_results.iterrows()
        ):

            user_id = row[
                "user_id"
            ]

            indicators = row.get(
                "indicators",
                ""
            )

            reason = (
                "Behaviour change detected: "
                f"{indicators}"
            )

            add_detection(
                detections,
                user_id,
                "Sudden Account Behaviour Change",
                row,
                reason
            )


    # ========================================================
    # NO DETECTIONS
    # ========================================================

    if not detections:

        return (
            pd.DataFrame(),
            pd.DataFrame()
        )


    # ========================================================
    # DETECTION DATAFRAME
    # ========================================================

    detections_df = pd.DataFrame(
        detections
    )


    # ========================================================
    # AGGREGATE BY USER
    # ========================================================

    risk_rows = []


    for user_id, user_events in (
        detections_df.groupby(
            "user_id"
        )
    ):

        # ----------------------------------------------------
        # Each detector counts only once
        # ----------------------------------------------------

        unique_events = (
            user_events
            .drop_duplicates(
                subset=[
                    "threat"
                ]
            )
        )


        # ----------------------------------------------------
        # Basic score
        # ----------------------------------------------------

        score = int(
            unique_events[
                "score_contribution"
            ].sum()
        )


        # ----------------------------------------------------
        # Detect combinations
        # ----------------------------------------------------

        threats = set(
            unique_events[
                "threat"
            ]
        )


        combination_bonus = 0

        combination_reasons = []


        # ----------------------------------------------------
        # Strong combination:
        #
        # password spraying
        # +
        # unusual location
        # ----------------------------------------------------

        if {
            "Password Spraying",
            "Unusual Login Location"
        }.issubset(threats):

            combination_bonus += 10

            combination_reasons.append(
                "Password spraying combined "
                "with unusual login location"
            )


        # ----------------------------------------------------
        # Strong combination:
        #
        # password spraying
        # +
        # new device
        # ----------------------------------------------------

        if {
            "Password Spraying",
            "Unknown / New Device"
        }.issubset(threats):

            combination_bonus += 10

            combination_reasons.append(
                "Password spraying combined "
                "with a new device"
            )


        # ----------------------------------------------------
        # Strong combination:
        #
        # location + device + session
        # ----------------------------------------------------

        if {
            "Unusual Login Location",
            "Unknown / New Device",
            "Suspicious Session Activity"
        }.issubset(threats):

            combination_bonus += 10

            combination_reasons.append(
                "Unusual location, new device, "
                "and suspicious session activity"
            )


        # ----------------------------------------------------
        # Failed login + new device
        # ----------------------------------------------------

        if {
            "Multiple Failed Login Attempts",
            "Unknown / New Device"
        }.issubset(threats):

            combination_bonus += 5

            combination_reasons.append(
                "Failed-login activity combined "
                "with a new device"
            )


        # ----------------------------------------------------
        # Failed login + unusual location
        # ----------------------------------------------------

        if {
            "Multiple Failed Login Attempts",
            "Unusual Login Location"
        }.issubset(threats):

            combination_bonus += 5

            combination_reasons.append(
                "Failed-login activity combined "
                "with an unusual location"
            )


        # ----------------------------------------------------
        # Apply combination bonus
        # ----------------------------------------------------

        score += combination_bonus


        # ----------------------------------------------------
        # Cap score
        # ----------------------------------------------------

        score = min(
            score,
            100
        )


        # ----------------------------------------------------
        # Determine level
        # ----------------------------------------------------

        risk_level = get_risk_level(
            score
        )


        # ----------------------------------------------------
        # Detector names
        # ----------------------------------------------------

        detectors_triggered = (
            unique_events[
                "threat"
            ]
            .tolist()
        )


        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        evidence = (
            unique_events[
                "reason"
            ]
            .drop_duplicates()
            .tolist()
        )


        # ----------------------------------------------------
        # Add combination evidence
        # ----------------------------------------------------

        evidence.extend(
            combination_reasons
        )


        # ----------------------------------------------------
        # Final user report
        # ----------------------------------------------------

        risk_rows.append({

            "user_id":
                user_id,

            "risk_score":
                score,

            "risk_level":
                risk_level,

            "detector_count":
                len(
                    detectors_triggered
                ),

            "detectors_triggered":
                ", ".join(
                    detectors_triggered
                ),

            "reasons":
                " | ".join(
                    evidence
                )
        })


    # ========================================================
    # FINAL REPORT
    # ========================================================

    risk_report = pd.DataFrame(
        risk_rows
    )


    # ========================================================
    # SORT BY RISK
    # ========================================================

    risk_report = (
        risk_report
        .sort_values(
            by=[
                "risk_score",
                "detector_count"
            ],
            ascending=[
                False,
                False
            ]
        )
        .reset_index(
            drop=True
        )
    )


    # ========================================================
    # RETURN
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
        "\nBase detector scores:"
    )

    for threat, score in (
        BASE_SCORES.items()
    ):

        print(
            f"{threat}: {score}"
        )

    print(
        "\nRisk engine loaded successfully."
    )

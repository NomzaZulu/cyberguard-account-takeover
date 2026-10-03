import pandas as pd
import numpy as np


# ============================================================
# CYBERGUARD RISK ENGINE
# ============================================================
#
# Purpose:
#   Combine individual Account Takeover detections into
#   an account-level risk assessment.
#
# Important:
#   This engine does NOT use:
#       - scenario
#       - is_anomaly
#       - attack_type
#
#   Risk is calculated only from detector evidence.
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40


# ============================================================
# DETECTOR WEIGHTS
# ============================================================

DETECTOR_WEIGHTS = {

    "Multiple Failed Login Attempts": 20,

    "Password Spraying": 25,

    "Unusual Login Location": 15,

    "Unknown / New Device": 15,

    "Suspicious Session Activity": 25,

    "Sudden Account Behaviour Change": 20,

}


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= HIGH_THRESHOLD:
        return "HIGH"

    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"

    return "LOW"


# ============================================================
# NORMALIZE RISK
# ============================================================

def normalize_risk(value):

    value = str(value).strip().upper()

    if value in {"HIGH", "MEDIUM", "LOW"}:
        return value

    return "LOW"


# ============================================================
# DETECTOR WEIGHT
# ============================================================

def get_detector_weight(threat):

    return DETECTOR_WEIGHTS.get(
        str(threat).strip(),
        10
    )


# ============================================================
# EVIDENCE BONUS
# ============================================================

def calculate_evidence_bonus(detection):

    bonus = 0

    threat = str(
        detection.get("threat", "")
    ).strip()

    risk = normalize_risk(
        detection.get("risk", "LOW")
    )

    # --------------------------------------------------------
    # Base risk bonus
    # --------------------------------------------------------

    if risk == "HIGH":
        bonus += 10

    elif risk == "MEDIUM":
        bonus += 5

    # --------------------------------------------------------
    # Multiple failed logins
    # --------------------------------------------------------

    if threat == "Multiple Failed Login Attempts":

        attempts = detection.get(
            "failed_attempts",
            0
        )

        try:
            attempts = int(attempts)
        except:
            attempts = 0

        if attempts >= 10:
            bonus += 8

        elif attempts >= 7:
            bonus += 5

        elif attempts >= 5:
            bonus += 2

    # --------------------------------------------------------
    # Password spraying
    # --------------------------------------------------------

    if threat == "Password Spraying":

        users = detection.get(
            "targeted_users",
            0
        )

        try:
            users = int(users)
        except:
            users = 0

        if users >= 15:
            bonus += 10

        elif users >= 10:
            bonus += 7

        elif users >= 5:
            bonus += 3

    # --------------------------------------------------------
    # Sudden behaviour change
    # --------------------------------------------------------

    if threat == "Sudden Account Behaviour Change":

        indicators = str(
            detection.get(
                "indicators",
                ""
            )
        )

        if indicators.strip():

            indicator_count = len([
                x for x in indicators.split(";")
                if x.strip()
            ])

            if indicator_count >= 4:
                bonus += 10

            elif indicator_count >= 3:
                bonus += 7

            elif indicator_count >= 2:
                bonus += 4

            elif indicator_count >= 1:
                bonus += 2

    # --------------------------------------------------------
    # Suspicious session
    # --------------------------------------------------------

    if threat == "Suspicious Session Activity":

        action = str(
            detection.get(
                "session_action",
                ""
            )
        ).strip().lower()

        if action == "privileged_action":
            bonus += 10

        elif action == "session_change":
            bonus += 3

    return bonus


# ============================================================
# REPEATED EVIDENCE BONUS
# ============================================================
#
# Important:
# Repeated detections should increase confidence, but should
# NOT allow one noisy detector to dominate the whole score.
#
# Therefore the bonus uses diminishing returns and a cap.
#
# Example:
#
#   1 detection  -> 0 bonus
#   2 detections -> +3
#   3 detections -> +5
#   4 detections -> +7
#   5+           -> capped at +10
#
# ============================================================

def calculate_repetition_bonus(
    detection_count,
    max_bonus=10
):

    try:
        count = int(detection_count)

    except:
        count = 0

    if count <= 1:
        return 0

    if count == 2:
        return 3

    if count == 3:
        return 5

    if count == 4:
        return 7

    return min(
        max_bonus,
        7 + min(count - 4, 3)
    )


# ============================================================
# CORRELATION BONUS
# ============================================================
#
# Multiple independent indicators are stronger than repeated
# instances of one indicator.
#
# ============================================================

def calculate_correlation_bonus(threats):

    threat_set = set(threats)

    bonus = 0

    # --------------------------------------------------------
    # Credential attack chain
    # --------------------------------------------------------

    if (
        "Multiple Failed Login Attempts"
        in threat_set
        and
        "Unknown / New Device"
        in threat_set
    ):
        bonus += 8

    # --------------------------------------------------------
    # Location + device anomaly
    # --------------------------------------------------------

    if (
        "Unusual Login Location"
        in threat_set
        and
        "Unknown / New Device"
        in threat_set
    ):
        bonus += 8

    # --------------------------------------------------------
    # Password spraying + suspicious session
    # --------------------------------------------------------

    if (
        "Password Spraying"
        in threat_set
        and
        "Suspicious Session Activity"
        in threat_set
    ):
        bonus += 12

    # --------------------------------------------------------
    # Failed logins + unusual location
    # --------------------------------------------------------

    if (
        "Multiple Failed Login Attempts"
        in threat_set
        and
        "Unusual Login Location"
        in threat_set
    ):
        bonus += 6

    # --------------------------------------------------------
    # Behaviour change + unknown device
    # --------------------------------------------------------

    if (
        "Sudden Account Behaviour Change"
        in threat_set
        and
        "Unknown / New Device"
        in threat_set
    ):
        bonus += 8

    # --------------------------------------------------------
    # Behaviour change + unusual location
    # --------------------------------------------------------

    if (
        "Sudden Account Behaviour Change"
        in threat_set
        and
        "Unusual Login Location"
        in threat_set
    ):
        bonus += 6

    # --------------------------------------------------------
    # Three or more independent detector types
    # --------------------------------------------------------

    if len(threat_set) >= 3:
        bonus += 10

    # --------------------------------------------------------
    # Four or more independent detector types
    # --------------------------------------------------------

    if len(threat_set) >= 4:
        bonus += 8

    return bonus


# ============================================================
# CAP SCORE
# ============================================================

def cap_score(score):

    return min(
        100,
        max(
            0,
            round(score)
        )
    )


# ============================================================
# BUILD EVIDENCE DESCRIPTION
# ============================================================

def build_evidence_description(
    detection
):

    threat = str(
        detection.get(
            "threat",
            "Unknown Threat"
        )
    )

    risk = normalize_risk(
        detection.get(
            "risk",
            "LOW"
        )
    )

    details = []

    # --------------------------------------------------------
    # Failed logins
    # --------------------------------------------------------

    if threat == "Multiple Failed Login Attempts":

        attempts = detection.get(
            "failed_attempts"
        )

        if pd.notna(attempts):

            details.append(
                f"{attempts} failed login attempts"
            )

    # --------------------------------------------------------
    # Password spraying
    # --------------------------------------------------------

    if threat == "Password Spraying":

        users = detection.get(
            "targeted_users"
        )

        if pd.notna(users):

            details.append(
                f"{users} targeted users"
            )

    # --------------------------------------------------------
    # Unusual location
    # --------------------------------------------------------

    if threat == "Unusual Login Location":

        location = detection.get(
            "detected_location"
        )

        if pd.notna(location):

            details.append(
                f"login from {location}"
            )

    # --------------------------------------------------------
    # Unknown device
    # --------------------------------------------------------

    if threat == "Unknown / New Device":

        device = detection.get(
            "detected_device"
        )

        if pd.notna(device):

            details.append(
                f"device {device}"
            )

    # --------------------------------------------------------
    # Suspicious session
    # --------------------------------------------------------

    if threat == "Suspicious Session Activity":

        action = detection.get(
            "session_action"
        )

        if pd.notna(action):

            details.append(
                f"session action: {action}"
            )

    # --------------------------------------------------------
    # Behaviour change
    # --------------------------------------------------------

    if threat == "Sudden Account Behaviour Change":

        indicators = detection.get(
            "indicators"
        )

        if pd.notna(indicators):

            details.append(
                str(indicators)
            )

    # --------------------------------------------------------
    # Final description
    # --------------------------------------------------------

    if details:

        return (
            f"{threat} ({risk}): "
            + "; ".join(details)
        )

    return (
        f"{threat} ({risk})"
    )


# ============================================================
# ACCOUNT RISK CALCULATION
# ============================================================

def calculate_account_risk(
    user_events
):

    if user_events is None:

        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "detections": 0,
            "detector_types": 0,
            "evidence": [],
            "reasons": []
        }

    if not isinstance(
        user_events,
        pd.DataFrame
    ):

        user_events = pd.DataFrame(
            user_events
        )

    if user_events.empty:

        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "detections": 0,
            "detector_types": 0,
            "evidence": [],
            "reasons": []
        }

    if "threat" not in user_events.columns:

        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "detections": 0,
            "detector_types": 0,
            "evidence": [],
            "reasons": []
        }

    events = user_events.copy()

    events["threat"] = (
        events["threat"]
        .astype(str)
        .str.strip()
    )

    events = events[
        events["threat"] != ""
    ].copy()

    if events.empty:

        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "detections": 0,
            "detector_types": 0,
            "evidence": [],
            "reasons": []
        }

    # ========================================================
    # FULL DETECTION COUNT
    # ========================================================
    #
    # IMPORTANT:
    # We retain ALL events here so repeated evidence can
    # contribute a bounded bonus.
    #
    # ========================================================

    total_detections = len(events)

    # ========================================================
    # DETECTOR COUNTS
    # ========================================================

    detector_counts = (
        events["threat"]
        .value_counts()
        .to_dict()
    )

    # ========================================================
    # UNIQUE DETECTOR TYPES
    # ========================================================

    unique_threats = list(
        detector_counts.keys()
    )

    detector_type_count = len(
        unique_threats
    )

    # ========================================================
    # REPRESENTATIVE DETECTIONS
    # ========================================================
    #
    # We use one representative row per detector for the
    # main evidence calculation.
    #
    # Repeated rows are handled separately through the
    # repetition bonus.
    #
    # ========================================================

    representative_events = (
        events
        .drop_duplicates(
            subset=["threat"]
        )
        .copy()
    )

    # ========================================================
    # BASE SCORE
    # ========================================================

    score = 0

    evidence = []

    reasons = []

    # ========================================================
    # DETECTOR SCORES
    # ========================================================

    for _, detection in (
        representative_events.iterrows()
    ):

        threat = str(
            detection["threat"]
        ).strip()

        weight = get_detector_weight(
            threat
        )

        evidence_bonus = (
            calculate_evidence_bonus(
                detection
            )
        )

        detector_score = (
            weight
            + evidence_bonus
        )

        score += detector_score

        # ----------------------------------------------------
        # Human-readable evidence
        # ----------------------------------------------------

        evidence_description = (
            build_evidence_description(
                detection
            )
        )

        evidence.append(
            evidence_description
        )

        reasons.append(
            {
                "threat": threat,
                "detector_weight": weight,
                "evidence_bonus": evidence_bonus,
                "score_contribution": detector_score,
                "occurrences": detector_counts.get(
                    threat,
                    1
                )
            }
        )

    # ========================================================
    # REPETITION BONUSES
    # ========================================================

    repetition_bonus_total = 0

    for threat, count in (
        detector_counts.items()
    ):

        repetition_bonus = (
            calculate_repetition_bonus(
                count
            )
        )

        repetition_bonus_total += (
            repetition_bonus
        )

        if repetition_bonus > 0:

            reasons.append(
                {
                    "threat": threat,
                    "detector_weight": 0,
                    "evidence_bonus": 0,
                    "repetition_bonus": repetition_bonus,
                    "score_contribution": repetition_bonus,
                    "occurrences": count
                }
            )

    # --------------------------------------------------------
    # Add bounded repetition score
    # --------------------------------------------------------

    score += repetition_bonus_total

    # ========================================================
    # CORRELATION BONUS
    # ========================================================

    correlation_bonus = (
        calculate_correlation_bonus(
            unique_threats
        )
    )

    score += correlation_bonus

    if correlation_bonus > 0:

        reasons.append(
            {
                "type": "correlation",
                "correlation_bonus": correlation_bonus,
                "score_contribution": correlation_bonus
            }
        )

    # ========================================================
    # DIMINISHING RETURNS
    # ========================================================
    #
    # Many independent detector types should increase risk,
    # but not linearly forever.
    #
    # ========================================================

    if detector_type_count >= 5:

        score += 8

        reasons.append(
            {
                "type": "multi_signal",
                "score_contribution": 8,
                "description": (
                    "Five or more independent "
                    "risk signals detected"
                )
            }
        )

    elif detector_type_count >= 4:

        score += 6

        reasons.append(
            {
                "type": "multi_signal",
                "score_contribution": 6,
                "description": (
                    "Four independent "
                    "risk signals detected"
                )
            }
        )

    elif detector_type_count >= 3:

        score += 4

        reasons.append(
            {
                "type": "multi_signal",
                "score_contribution": 4,
                "description": (
                    "Three independent "
                    "risk signals detected"
                )
            }
        )

    # ========================================================
    # HIGH-RISK SESSION ESCALATION
    # ========================================================

    privileged_session = events[
        (
            events["threat"]
            == "Suspicious Session Activity"
        )
        &
        (
            events.get(
                "session_action",
                pd.Series(
                    index=events.index,
                    dtype="object"
                )
            )
            .astype(str)
            .str.lower()
            .eq("privileged_action")
        )
    ]

    if not privileged_session.empty:

        score += 8

        reasons.append(
            {
                "type": "privileged_session",
                "score_contribution": 8,
                "description": (
                    "Privileged session activity detected"
                )
            }
        )

    # ========================================================
    # SCORE CAP
    # ========================================================

    score = cap_score(
        score
    )

    # ========================================================
    # FINAL RISK LEVEL
    # ========================================================

    risk_level = get_risk_level(
        score
    )

    # ========================================================
    # RESULT
    # ========================================================

    return {

        "risk_score": score,

        "risk_level": risk_level,

        "detections": total_detections,

        "detector_types": detector_type_count,

        "evidence": evidence,

        "reasons": reasons,

        "detector_counts": detector_counts,

        "repetition_bonus": repetition_bonus_total,

        "correlation_bonus": correlation_bonus
    }


# ============================================================
# ANALYZE ALL ACCOUNTS
# ============================================================

def analyze_account_risk(
    detections
):

    if detections is None:

        return pd.DataFrame()

    if not isinstance(
        detections,
        pd.DataFrame
    ):

        detections = pd.DataFrame(
            detections
        )

    if detections.empty:

        return pd.DataFrame()

    if "user_id" not in detections.columns:

        return pd.DataFrame()

    results = []

    # ========================================================
    # USER LEVEL ANALYSIS
    # ========================================================

    for user_id, user_events in (
        detections.groupby("user_id")
    ):

        risk = calculate_account_risk(
            user_events
        )

        results.append(
            {
                "user_id": user_id,

                "risk_score": risk[
                    "risk_score"
                ],

                "risk_level": risk[
                    "risk_level"
                ],

                "detections": risk[
                    "detections"
                ],

                "detector_types": risk[
                    "detector_types"
                ],

                "evidence": risk[
                    "evidence"
                ],

                "reasons": risk[
                    "reasons"
                ],

                "detector_counts": risk[
                    "detector_counts"
                ],

                "repetition_bonus": risk[
                    "repetition_bonus"
                ],

                "correlation_bonus": risk[
                    "correlation_bonus"
                ]
            }
        )

    # ========================================================
    # DATAFRAME
    # ========================================================

    result_df = pd.DataFrame(
        results
    )

    # ========================================================
    # SORT BY RISK
    # ========================================================

    if not result_df.empty:

        risk_order = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }

        result_df["_risk_order"] = (
            result_df["risk_level"]
            .map(risk_order)
            .fillna(0)
        )

        result_df = (
            result_df
            .sort_values(
                [
                    "_risk_order",
                    "risk_score"
                ],
                ascending=[
                    False,
                    False
                ]
            )
            .drop(
                columns=[
                    "_risk_order"
                ]
            )
            .reset_index(
                drop=True
            )
        )

    return result_df


# ============================================================
# MAIN RISK ENGINE ENTRY POINT
# ============================================================

def run_risk_engine(
    detections
):

    return analyze_account_risk(
        detections
    )


# ============================================================
# BACKWARD-COMPATIBILITY ALIASES
# ============================================================

calculate_risk = calculate_account_risk

analyze_risks = analyze_account_risk

run = run_risk_engine

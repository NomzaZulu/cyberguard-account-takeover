import streamlit as st
import pandas as pd

from account_takeover_engine import (
    detect_multiple_failed_logins,
    detect_password_spraying,
    detect_unusual_locations,
    detect_unknown_devices,
    detect_suspicious_sessions,
    detect_sudden_account_behaviour
)

from risk_engine import build_risk_report


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberGuard - Account Takeover Detection",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 700;
        margin-bottom: 0px;
    }

    .subtitle {
        font-size: 20px;
        opacity: 0.75;
        margin-top: 0px;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 650;
        margin-top: 25px;
        margin-bottom: 15px;
    }

    .risk-card {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid rgba(128,128,128,0.25);
        margin-bottom: 15px;
    }

    .risk-title {
        font-size: 22px;
        font-weight: 650;
    }

    .risk-score {
        font-size: 32px;
        font-weight: 700;
    }

    .small-muted {
        opacity: 0.65;
        font-size: 14px;
    }

    .indicator-box {
        padding: 12px 16px;
        border-radius: 8px;
        border: 1px solid rgba(128,128,128,0.20);
        margin-bottom: 8px;
    }

    .evidence-box {
        padding: 12px 16px;
        border-radius: 8px;
        border-left: 4px solid rgba(128,128,128,0.55);
        margin-bottom: 8px;
    }

    .recommendation-box {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid rgba(128,128,128,0.25);
        margin-top: 15px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_risk_icon(level):
    level = str(level).upper()

    if level == "HIGH":
        return "🔴"

    if level == "MEDIUM":
        return "🟠"

    return "🟢"


def get_recommendations(detectors):
    """
    Generate human-readable response recommendations
    from the detectors that were triggered.
    """

    detectors_text = str(detectors).lower()

    recommendations = []

    if "multiple failed login" in detectors_text:
        recommendations.append(
            "Review recent failed-login activity and verify whether "
            "the affected account is under attack."
        )

    if "password spraying" in detectors_text:
        recommendations.append(
            "Investigate the source IP and consider temporarily "
            "blocking or rate-limiting the suspicious source."
        )

    if "unusual login location" in detectors_text:
        recommendations.append(
            "Verify the login location with the account owner."
        )

    if "unknown / new device" in detectors_text:
        recommendations.append(
            "Verify the new device and require additional "
            "authentication if the device is not recognised."
        )

    if "suspicious session" in detectors_text:
        recommendations.append(
            "Review the affected session and consider revoking "
            "the session if the activity is unauthorised."
        )

    if "sudden account behaviour" in detectors_text:
        recommendations.append(
            "Investigate the recent behavioural change against "
            "the user's historical activity."
        )

    if not recommendations:
        recommendations.append(
            "Continue monitoring the account for additional "
            "suspicious activity."
        )

    return recommendations


def render_indicator_list(detectors):
    """
    Render detector names in a clean user-facing format.
    """

    if pd.isna(detectors):
        return

    detector_list = [
        item.strip()
        for item in str(detectors).split(",")
        if item.strip()
    ]

    for detector in detector_list:
        st.markdown(
            f"""
            <div class="indicator-box">
                🔎 <strong>{detector}</strong>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_evidence_list(reasons):
    """
    Render evidence/reasons as readable evidence cards.
    """

    if pd.isna(reasons):
        return

    reason_list = [
        item.strip()
        for item in str(reasons).split(" | ")
        if item.strip()
    ]

    for reason in reason_list:
        st.markdown(
            f"""
            <div class="evidence-box">
                {reason}
            </div>
            """,
            unsafe_allow_html=True
        )


def render_account_report(report):
    """
    Render one complete human-readable account security report.
    """

    user_id = report["user_id"]
    score = int(report["risk_score"])
    level = str(report["risk_level"]).upper()
    detector_count = int(report["detector_count"])

    icon = get_risk_icon(level)

    st.markdown(
        f"""
        <div class="risk-card">

            <div class="risk-title">
                {icon} Account Security Assessment
            </div>

            <div class="small-muted">
                User ID: {user_id}
            </div>

            <br>

            <div class="risk-score">
                {score}/100
            </div>

            <div>
                <strong>{level} RISK</strong>
                &nbsp; • &nbsp;
                {detector_count} detector(s) triggered
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    st.progress(
        min(max(score, 0), 100) / 100
    )

    # --------------------------------------------------------
    # INDICATORS
    # --------------------------------------------------------

    st.markdown("#### Detected Indicators")

    render_indicator_list(
        report["detectors_triggered"]
    )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    st.markdown("#### Why CyberGuard Flagged This Account")

    render_evidence_list(
        report["reasons"]
    )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    st.markdown("#### Recommended Response")

    recommendations = get_recommendations(
        report["detectors_triggered"]
    )

    for recommendation in recommendations:

        st.markdown(
            f"""
            <div class="recommendation-box">
                🛡️ {recommendation}
            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CyberGuard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Credential Theft & Account Takeover Detection'
    '</div>',
    unsafe_allow_html=True
)

st.write(
    "Analyse organisation authentication activity and identify "
    "behavioural indicators associated with credential theft "
    "and account takeover."
)


# ============================================================
# FILE UPLOAD
# ============================================================

st.markdown(
    '<div class="section-title">📂 Upload Security Data</div>',
    unsafe_allow_html=True
)

col1, col2 = st.columns(2)

with col1:

    st.markdown("### Organisation Profiles")

    profiles_file = st.file_uploader(
        "Upload organisation profiles CSV",
        type=["csv"],
        key="profiles"
    )

with col2:

    st.markdown("### Login Events")

    events_file = st.file_uploader(
        "Upload login events CSV",
        type=["csv"],
        key="events"
    )


# ============================================================
# MAIN APPLICATION
# ============================================================

if profiles_file is not None and events_file is not None:

    try:

        # ----------------------------------------------------
        # LOAD DATA
        # ----------------------------------------------------

        profiles = pd.read_csv(
            profiles_file
        )

        events = pd.read_csv(
            events_file
        )

        st.success(
            "Both security datasets uploaded successfully."
        )


        # ====================================================
        # ORGANISATION OVERVIEW
        # ====================================================

        st.markdown(
            '<div class="section-title">'
            '📊 Organisation Overview'
            '</div>',
            unsafe_allow_html=True
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.metric(
                "Organisation Users",
                len(profiles)
            )

        with col2:

            st.metric(
                "Login Events",
                len(events)
            )

        with col3:

            if "user_id" in events.columns:

                unique_users = events[
                    "user_id"
                ].nunique()

            else:

                unique_users = 0

            st.metric(
                "Unique Users",
                unique_users
            )

        with col4:

            if "ip_address" in events.columns:

                unique_ips = events[
                    "ip_address"
                ].nunique()

            else:

                unique_ips = 0

            st.metric(
                "Source IPs",
                unique_ips
            )


        # ====================================================
        # DATASET PREVIEW
        # ====================================================

        with st.expander(
            "View Uploaded Data"
        ):

            tab1, tab2 = st.tabs(
                [
                    "Organisation Profiles",
                    "Login Events"
                ]
            )

            with tab1:

                st.dataframe(
                    profiles,
                    use_container_width=True,
                    height=300
                )

            with tab2:

                st.dataframe(
                    events.head(100),
                    use_container_width=True,
                    height=300
                )


        # ====================================================
        # ANALYZE BUTTON
        # ====================================================

        st.markdown(
            '<div class="section-title">'
            '🔍 Account Takeover Analysis'
            '</div>',
            unsafe_allow_html=True
        )

        analyze_button = st.button(
            "🚀 Analyze Account Activity",
            use_container_width=True,
            type="primary"
        )


        # ====================================================
        # RUN ANALYSIS
        # ====================================================

        if analyze_button:

            with st.spinner(
                "CyberGuard is analysing authentication activity..."
            ):

                # ============================================
                # DETECTOR 1
                # ============================================

                failed_login_results = (
                    detect_multiple_failed_logins(
                        events
                    )
                )


                # ============================================
                # DETECTOR 2
                # ============================================

                password_spraying_results = (
                    detect_password_spraying(
                        events
                    )
                )


                # ============================================
                # DETECTOR 3
                # ============================================

                unusual_location_results = (
                    detect_unusual_locations(
                        events,
                        profiles
                    )
                )


                # ============================================
                # DETECTOR 4
                # ============================================

                unknown_device_results = (
                    detect_unknown_devices(
                        events,
                        profiles
                    )
                )


                # ============================================
                # DETECTOR 5
                # ============================================

                suspicious_session_results = (
                    detect_suspicious_sessions(
                        events
                    )
                )


                # ============================================
                # DETECTOR 6
                # ============================================

                behaviour_change_results = (
                    detect_sudden_account_behaviour(
                        events
                    )
                )


                # ============================================
                # RISK ENGINE
                # ============================================

                risk_report, detection_details = (
                    build_risk_report(
                        failed_login_results,
                        password_spraying_results,
                        unusual_location_results,
                        unknown_device_results,
                        suspicious_session_results,
                        behaviour_change_results
                    )
                )


            # =================================================
            # ANALYSIS COMPLETE
            # =================================================

            st.success(
                "Analysis completed successfully."
            )


            # =================================================
            # NO DETECTIONS
            # =================================================

            if risk_report.empty:

                st.success(
                    "🟢 No suspicious account activity detected."
                )

                st.info(
                    "CyberGuard did not identify any of the "
                    "configured account-takeover indicators "
                    "in the supplied authentication data."
                )


            # =================================================
            # DETECTIONS FOUND
            # =================================================

            else:

                # =============================================
                # CALCULATE SUMMARY
                # =============================================

                high_count = len(
                    risk_report[
                        risk_report["risk_level"] == "HIGH"
                    ]
                )

                medium_count = len(
                    risk_report[
                        risk_report["risk_level"] == "MEDIUM"
                    ]
                )

                low_count = len(
                    risk_report[
                        risk_report["risk_level"] == "LOW"
                    ]
                )

                total_risky_accounts = len(
                    risk_report
                )

                total_detections = len(
                    detection_details
                )


                # =============================================
                # SECURITY STATUS
                # =============================================

                st.markdown(
                    '<div class="section-title">'
                    '🚨 CyberGuard Security Status'
                    '</div>',
                    unsafe_allow_html=True
                )

                if high_count > 0:

                    st.error(
                        f"🔴 {high_count} high-risk account(s) "
                        "require investigation."
                    )

                elif medium_count > 0:

                    st.warning(
                        f"🟠 {medium_count} medium-risk account(s) "
                        "require review."
                    )

                else:

                    st.info(
                        "🟢 Suspicious activity was detected, "
                        "but no account reached the high-risk threshold."
                    )


                # =============================================
                # RISK OVERVIEW
                # =============================================

                st.markdown(
                    "### Risk Overview"
                )

                col1, col2, col3, col4 = st.columns(4)

                with col1:

                    st.metric(
                        "High Risk",
                        high_count
                    )

                with col2:

                    st.metric(
                        "Medium Risk",
                        medium_count
                    )

                with col3:

                    st.metric(
                        "Low Risk",
                        low_count
                    )

                with col4:

                    st.metric(
                        "Accounts Flagged",
                        total_risky_accounts
                    )


                # =============================================
                # DETECTION OVERVIEW
                # =============================================

                st.markdown(
                    "### Detection Overview"
                )

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "Detection Events",
                        total_detections
                    )

                with col2:

                    st.metric(
                        "Users Analysed",
                        events["user_id"].nunique()
                        if "user_id" in events.columns
                        else 0
                    )

                with col3:

                    st.metric(
                        "Detector Types",
                        6
                    )


                # =============================================
                # PRIORITY ACCOUNTS
                # =============================================

                st.markdown(
                    "### 🚨 Priority Accounts"
                )

                priority_columns = [
                    "user_id",
                    "risk_score",
                    "risk_level",
                    "detector_count"
                ]

                priority_table = (
                    risk_report[
                        priority_columns
                    ]
                    .copy()
                )

                priority_table.columns = [
                    "User",
                    "Risk Score",
                    "Risk Level",
                    "Detectors"
                ]

                st.dataframe(
                    priority_table,
                    use_container_width=True,
                    hide_index=True
                )


                # =============================================
                # ACCOUNT SECURITY REPORTS
                # =============================================

                st.markdown(
                    "### 👤 Account Security Assessments"
                )

                st.caption(
                    "Open an account to view the evidence "
                    "behind its risk assessment."
                )


                for _, report in risk_report.iterrows():

                    user_id = report["user_id"]
                    score = int(
                        report["risk_score"]
                    )
                    level = str(
                        report["risk_level"]
                    ).upper()

                    icon = get_risk_icon(
                        level
                    )

                    detector_count = int(
                        report["detector_count"]
                    )

                    with st.expander(
                        f"{icon} User {user_id} — "
                        f"{level} Risk — "
                        f"{score}/100 — "
                        f"{detector_count} detector(s)"
                    ):

                        render_account_report(
                            report
                        )


                # =============================================
                # TECHNICAL DETECTOR RESULTS
                # =============================================

                st.markdown(
                    "### 🔧 Technical Detection Results"
                )

                st.caption(
                    "These tables are intended for technical "
                    "verification and debugging. Normal users "
                    "do not need to inspect them."
                )


                with st.expander(
                    "Detector 1 — Multiple Failed Login Attempts"
                ):

                    if failed_login_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            failed_login_results,
                            use_container_width=True
                        )


                with st.expander(
                    "Detector 2 — Password Spraying"
                ):

                    if password_spraying_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            password_spraying_results,
                            use_container_width=True
                        )


                with st.expander(
                    "Detector 3 — Unusual Login Location"
                ):

                    if unusual_location_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            unusual_location_results,
                            use_container_width=True
                        )


                with st.expander(
                    "Detector 4 — Unknown / New Device"
                ):

                    if unknown_device_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            unknown_device_results,
                            use_container_width=True
                        )


                with st.expander(
                    "Detector 5 — Suspicious Session Activity"
                ):

                    if suspicious_session_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            suspicious_session_results,
                            use_container_width=True
                        )


                with st.expander(
                    "Detector 6 — Sudden Account Behaviour Change"
                ):

                    if behaviour_change_results.empty:

                        st.success(
                            "No detections."
                        )

                    else:

                        st.dataframe(
                            behaviour_change_results,
                            use_container_width=True
                        )


                # =============================================
                # COMBINED DETECTION EVIDENCE
                # =============================================

                with st.expander(
                    "🧪 View Combined Detection Evidence"
                ):

                    if detection_details.empty:

                        st.info(
                            "No combined detection evidence available."
                        )

                    else:

                        st.dataframe(
                            detection_details,
                            use_container_width=True,
                            hide_index=True
                        )


                # =============================================
                # FINAL STATUS
                # =============================================

                st.markdown("---")

                st.markdown(
                    "### 🛡️ Final CyberGuard Assessment"
                )

                if high_count > 0:

                    st.error(
                        "🔴 CyberGuard identified high-risk "
                        "account activity requiring investigation."
                    )

                    st.write(
                        f"{high_count} account(s) reached the "
                        "high-risk threshold based on multiple "
                        "authentication and behavioural indicators."
                    )

                elif medium_count > 0:

                    st.warning(
                        "🟠 CyberGuard identified suspicious "
                        "account activity requiring review."
                    )

                    st.write(
                        f"{medium_count} account(s) reached the "
                        "medium-risk threshold."
                    )

                else:

                    st.info(
                        "🟢 CyberGuard detected suspicious signals "
                        "but no account reached the high-risk threshold."
                    )


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as e:

        st.error(
            "An error occurred while analysing the datasets."
        )

        with st.expander(
            "View Technical Error"
        ):

            st.code(
                str(e)
            )


# ============================================================
# WAITING STATE
# ============================================================

else:

    st.info(
        "Upload both the organisation profiles CSV and "
        "login events CSV to begin account takeover analysis."
    )

    st.markdown(
        """
        ### What CyberGuard analyses

        **Six account-takeover indicators:**

        1. Multiple failed login attempts
        2. Password spraying
        3. Unusual login locations
        4. Unknown or new devices
        5. Suspicious session activity
        6. Sudden account behaviour changes

        CyberGuard combines these signals into an explainable
        account-level risk assessment.
        """
    )

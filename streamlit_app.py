import streamlit as st
import pandas as pd

from account_takeover_service import (
    analyze_account_takeover
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberGuard - Account Takeover Detection",
    page_icon="🛡️",
    layout="wide"
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


def render_list_items(items):

    if not items:
        st.write("None")

        return

    for item in items:

        st.write(
            f"• {item}"
        )


def render_account_report(account):

    user_id = account.get(
        "user_id",
        "Unknown"
    )

    score = int(
        account.get(
            "risk_score",
            0
        )
    )

    level = str(
        account.get(
            "risk_level",
            "LOW"
        )
    ).upper()

    detector_count = int(
        account.get(
            "detector_count",
            0
        )
    )

    icon = get_risk_icon(
        level
    )


    # --------------------------------------------------------
    # ACCOUNT SUMMARY
    # --------------------------------------------------------

    st.markdown(
        f"""
        ### {icon} Account Security Assessment

        **User ID:** `{user_id}`

        **Risk Level:** {level}

        **Risk Score:** {score}/100

        **Detectors Triggered:** {detector_count}
        """
    )


    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    st.progress(
        min(
            max(
                score,
                0
            ),
            100
        ) / 100
    )


    # --------------------------------------------------------
    # INDICATORS
    # --------------------------------------------------------

    st.markdown(
        "#### Detected Indicators"
    )

    detectors = account.get(
        "detectors_triggered",
        []
    )

    if isinstance(
        detectors,
        str
    ):

        detectors = [
            x.strip()
            for x in detectors.split(",")
            if x.strip()
        ]

    render_list_items(
        detectors
    )


    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    st.markdown(
        "#### Why CyberGuard Flagged This Account"
    )

    reasons = account.get(
        "reasons",
        []
    )

    if isinstance(
        reasons,
        str
    ):

        reasons = [
            x.strip()
            for x in reasons.split("|")
            if x.strip()
        ]

    render_list_items(
        reasons
    )


    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    st.markdown(
        "#### Recommended Response"
    )

    recommendations = []


    detector_text = " ".join(
        str(x)
        for x in detectors
    ).lower()


    if (
        "password spraying"
        in detector_text
        or
        "multiple failed login"
        in detector_text
    ):

        recommendations.extend([
            "Review recent authentication attempts.",
            "Consider forcing a password reset if the activity is confirmed unauthorized."
        ])


    if (
        "unknown / new device"
        in detector_text
    ):

        recommendations.append(
            "Verify the newly observed device."
        )


    if (
        "unusual login location"
        in detector_text
    ):

        recommendations.append(
            "Verify whether the unusual login location is legitimate."
        )


    if (
        "suspicious session activity"
        in detector_text
    ):

        recommendations.append(
            "Review and revoke suspicious active sessions if necessary."
        )


    if (
        "sudden account behaviour change"
        in detector_text
    ):

        recommendations.append(
            "Review recent account activity for additional anomalies."
        )


    if not recommendations:

        recommendations.append(
            "Review the account activity and verify whether the detected behaviour is legitimate."
        )


    for recommendation in recommendations:

        st.info(
            f"🛡️ {recommendation}"
        )


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ CyberGuard"
)

st.subheader(
    "Credential Theft & Account Takeover Detection"
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
    "## 📂 Upload Security Data"
)

col1, col2 = st.columns(2)


with col1:

    st.markdown(
        "### Organisation Profiles"
    )

    profiles_file = st.file_uploader(
        "Upload organisation profiles CSV",
        type=["csv"],
        key="profiles"
    )


with col2:

    st.markdown(
        "### Login Events"
    )

    events_file = st.file_uploader(
        "Upload login events CSV",
        type=["csv"],
        key="events"
    )


# ============================================================
# MAIN APPLICATION
# ============================================================

if (
    profiles_file is not None
    and
    events_file is not None
):

    try:

        # ====================================================
        # LOAD DATA
        # ====================================================

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
            "## 📊 Organisation Overview"
        )


        col1, col2, col3, col4 = (
            st.columns(4)
        )


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

            unique_users = (
                events["user_id"].nunique()
                if "user_id"
                in events.columns
                else 0
            )

            st.metric(
                "Unique Users",
                unique_users
            )


        with col4:

            unique_ips = (
                events["ip_address"].nunique()
                if "ip_address"
                in events.columns
                else 0
            )

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
            "## 🔍 Account Takeover Analysis"
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
                # NEW SERVICE LAYER
                # ============================================

                result = analyze_account_takeover(
                    events,
                    profiles
                )


            st.success(
                "Analysis completed successfully."
            )


            # =================================================
            # EXTRACT RESULT
            # =================================================

            summary = result.get(
                "summary",
                {}
            )

            accounts = result.get(
                "accounts",
                []
            )

            detections = result.get(
                "detections",
                []
            )


            # =================================================
            # SERVICE TEST STATUS
            # =================================================

            st.markdown(
                "## 🔌 Service Layer Status"
            )

            st.success(
                "Account Takeover Service executed successfully."
            )


            service_col1, service_col2, service_col3 = (
                st.columns(3)
            )


            with service_col1:

                st.metric(
                    "Accounts Returned",
                    len(accounts)
                )


            with service_col2:

                st.metric(
                    "Detections Returned",
                    len(detections)
                )


            with service_col3:

                st.metric(
                    "Detector Types",
                    summary.get(
                        "detector_types",
                        6
                    )
                )


            # =================================================
            # NO DETECTIONS
            # =================================================

            if not accounts:

                st.success(
                    "🟢 No suspicious account activity detected."
                )

                st.info(
                    "CyberGuard did not identify any configured "
                    "account-takeover indicators in the supplied "
                    "authentication data."
                )


            # =================================================
            # DETECTIONS FOUND
            # =================================================

            else:

                # =============================================
                # SECURITY STATUS
                # =============================================

                st.markdown(
                    "## 🚨 CyberGuard Security Status"
                )


                high_count = summary.get(
                    "high_risk",
                    0
                )

                medium_count = summary.get(
                    "medium_risk",
                    0
                )

                low_count = summary.get(
                    "low_risk",
                    0
                )

                accounts_flagged = summary.get(
                    "accounts_flagged",
                    len(accounts)
                )

                detection_events = summary.get(
                    "detection_events",
                    len(detections)
                )


                if high_count > 0:

                    st.error(
                        f"🔴 {high_count} high-risk "
                        "account(s) require investigation."
                    )

                elif medium_count > 0:

                    st.warning(
                        f"🟠 {medium_count} medium-risk "
                        "account(s) require review."
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


                col1, col2, col3, col4 = (
                    st.columns(4)
                )


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
                        accounts_flagged
                    )


                # =============================================
                # DETECTION OVERVIEW
                # =============================================

                st.markdown(
                    "### Detection Overview"
                )


                col1, col2, col3 = (
                    st.columns(3)
                )


                with col1:

                    st.metric(
                        "Detection Events",
                        detection_events
                    )


                with col2:

                    st.metric(
                        "Users Analysed",
                        summary.get(
                            "users_analyzed",
                            0
                        )
                    )


                with col3:

                    st.metric(
                        "Detector Types",
                        summary.get(
                            "detector_types",
                            6
                        )
                    )


                # =============================================
                # PRIORITY ACCOUNTS
                # =============================================

                st.markdown(
                    "### 🚨 Priority Accounts"
                )


                priority_rows = []


                for account in accounts:

                    priority_rows.append({

                        "User":
                            account.get(
                                "user_id"
                            ),

                        "Risk Score":
                            account.get(
                                "risk_score"
                            ),

                        "Risk Level":
                            account.get(
                                "risk_level"
                            ),

                        "Detectors":
                            account.get(
                                "detector_count"
                            )
                    })


                priority_table = pd.DataFrame(
                    priority_rows
                )


                st.dataframe(
                    priority_table,
                    use_container_width=True,
                    hide_index=True
                )


                # =============================================
                # ACCOUNT SECURITY ASSESSMENTS
                # =============================================

                st.markdown(
                    "### 👤 Account Security Assessments"
                )


                st.caption(
                    "Open an account to view the evidence "
                    "behind its risk assessment."
                )


                for account in accounts:

                    user_id = account.get(
                        "user_id",
                        "Unknown"
                    )

                    score = int(
                        account.get(
                            "risk_score",
                            0
                        )
                    )

                    level = str(
                        account.get(
                            "risk_level",
                            "LOW"
                        )
                    ).upper()

                    detector_count = int(
                        account.get(
                            "detector_count",
                            0
                        )
                    )

                    icon = get_risk_icon(
                        level
                    )


                    with st.expander(
                        f"{icon} User {user_id} — "
                        f"{level} Risk — "
                        f"{score}/100 — "
                        f"{detector_count} detector(s)"
                    ):

                        render_account_report(
                            account
                        )


                # =============================================
                # TECHNICAL SERVICE OUTPUT
                # =============================================

                st.markdown(
                    "### 🔧 Technical Verification"
                )

                st.caption(
                    "These sections are for testing and debugging "
                    "the detection pipeline. They will not be part "
                    "of the final CyberGuard user interface."
                )


                # ---------------------------------------------
                # STRUCTURED SUMMARY
                # ---------------------------------------------

                with st.expander(
                    "View Service Summary"
                ):

                    st.json(
                        summary
                    )


                # ---------------------------------------------
                # COMBINED DETECTION EVIDENCE
                # ---------------------------------------------

                with st.expander(
                    "🧪 View Combined Detection Evidence"
                ):

                    if not detections:

                        st.info(
                            "No combined detection evidence available."
                        )

                    else:

                        detection_dataframe = pd.DataFrame(
                            detections
                        )

                        st.dataframe(
                            detection_dataframe,
                            use_container_width=True,
                            hide_index=True
                        )


                # ---------------------------------------------
                # FULL SERVICE RESULT
                # ---------------------------------------------

                with st.expander(
                    "🧩 View Full Service Result"
                ):

                    st.json(
                        result
                    )


                # =============================================
                # FINAL STATUS
                # =============================================

                st.markdown("---")

                st.markdown(
                    "## 🛡️ Final CyberGuard Assessment"
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
                        "🟢 Suspicious activity was detected, "
                        "but no account reached the high-risk threshold."
                    )


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

        CyberGuard combines these signals into an
        explainable account-level risk assessment.
        """
    )

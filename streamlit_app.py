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
# HEADER
# ============================================================

st.title("🛡️ CyberGuard")

st.subheader(
    "Credential Theft & Account Takeover Detection"
)

st.write(
    "Analyse organisation login activity and detect "
    "credential theft and account takeover indicators."
)


# ============================================================
# FILE UPLOAD
# ============================================================

st.markdown("## Upload Data")

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
# MAIN ANALYSIS
# ============================================================

if profiles_file is not None and events_file is not None:

    try:

        profiles = pd.read_csv(
            profiles_file
        )

        events = pd.read_csv(
            events_file
        )

        st.success(
            "Both datasets uploaded successfully."
        )


        # ====================================================
        # ORGANISATION OVERVIEW
        # ====================================================

        st.markdown("## Organisation Overview")

        col1, col2, col3 = st.columns(3)


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

            st.metric(
                "Unique Users",
                events["user_id"].nunique()
            )


        # ====================================================
        # DATASET PREVIEW
        # ====================================================

        st.markdown("## Dataset Preview")


        with st.expander(
            "View Organisation Profiles"
        ):

            st.dataframe(
                profiles,
                use_container_width=True
            )


        with st.expander(
            "View Login Events"
        ):

            st.dataframe(
                events.head(100),
                use_container_width=True
            )


        # ====================================================
        # ANALYZE BUTTON
        # ====================================================

        st.markdown(
            "## Account Takeover Analysis"
        )

        analyze_button = st.button(
            "🔍 Analyze Account Activity",
            use_container_width=True
        )


        if analyze_button:

            # =================================================
            # DETECTOR 1
            # =================================================

            st.markdown(
                "### Detector 1 — Multiple Failed Login Attempts"
            )

            failed_login_results = (
                detect_multiple_failed_logins(
                    events
                )
            )


            if failed_login_results.empty:

                st.success(
                    "No multiple failed-login attacks detected."
                )

            else:

                st.error(
                    f"{len(failed_login_results)} "
                    "suspicious user(s) detected."
                )

                st.dataframe(
                    failed_login_results,
                    use_container_width=True
                )


            # =================================================
            # DETECTOR 2
            # =================================================

            st.markdown(
                "### Detector 2 — Password Spraying"
            )

            password_spraying_results = (
                detect_password_spraying(
                    events
                )
            )


            if password_spraying_results.empty:

                st.success(
                    "No password spraying detected."
                )

            else:

                st.error(
                    f"{len(password_spraying_results)} "
                    "possible password spraying attack(s) detected."
                )

                st.dataframe(
                    password_spraying_results,
                    use_container_width=True
                )


            # =================================================
            # DETECTOR 3
            # =================================================

            st.markdown(
                "### Detector 3 — Unusual Login Location"
            )

            unusual_location_results = (
                detect_unusual_locations(
                    events,
                    profiles
                )
            )


            if unusual_location_results.empty:

                st.success(
                    "No unusual login locations detected."
                )

            else:

                st.warning(
                    f"{len(unusual_location_results)} "
                    "unusual login location(s) detected."
                )

                st.dataframe(
                    unusual_location_results,
                    use_container_width=True
                )


            # =================================================
            # DETECTOR 4
            # =================================================

            st.markdown(
                "### Detector 4 — Unknown / New Device"
            )

            unknown_device_results = (
                detect_unknown_devices(
                    events,
                    profiles
                )
            )


            if unknown_device_results.empty:

                st.success(
                    "No unknown or new devices detected."
                )

            else:

                st.warning(
                    f"{len(unknown_device_results)} "
                    "unknown/new device event(s) detected."
                )

                st.dataframe(
                    unknown_device_results,
                    use_container_width=True
                )


            # =================================================
            # DETECTOR 5
            # =================================================

            st.markdown(
                "### Detector 5 — Suspicious Session Activity"
            )

            suspicious_session_results = (
                detect_suspicious_sessions(
                    events
                )
            )


            if suspicious_session_results.empty:

                st.success(
                    "No suspicious session activity detected."
                )

            else:

                st.warning(
                    f"{len(suspicious_session_results)} "
                    "suspicious session(s) detected."
                )

                st.dataframe(
                    suspicious_session_results,
                    use_container_width=True
                )


            # =================================================
            # DETECTOR 6
            # =================================================

            st.markdown(
                "### Detector 6 — Sudden Account Behaviour Change"
            )

            behaviour_change_results = (
                detect_sudden_account_behaviour(
                    events
                )
            )


            if behaviour_change_results.empty:

                st.success(
                    "No significant account behaviour changes detected."
                )

            else:

                st.warning(
                    f"{len(behaviour_change_results)} "
                    "account behaviour change(s) detected."
                )

                st.dataframe(
                    behaviour_change_results,
                    use_container_width=True
                )


            # =================================================
            # CONSOLIDATED RISK ENGINE
            # =================================================

            st.markdown("---")

            st.markdown(
                "## 🛡️ CyberGuard Risk Assessment"
            )

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
            # NO RISK
            # =================================================

            if risk_report.empty:

                st.success(
                    "No suspicious account activity detected."
                )


            # =================================================
            # RISK DETECTED
            # =================================================

            else:

                st.warning(
                    f"{len(risk_report)} "
                    "account risk profile(s) generated."
                )


                # ---------------------------------------------
                # Risk table
                # ---------------------------------------------

                st.dataframe(
                    risk_report,
                    use_container_width=True
                )


                # =================================================
                # SUMMARY METRICS
                # =================================================

                st.markdown(
                    "### Risk Overview"
                )

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


                col1, col2, col3 = st.columns(3)


                with col1:

                    st.metric(
                        "HIGH Risk",
                        high_count
                    )


                with col2:

                    st.metric(
                        "MEDIUM Risk",
                        medium_count
                    )


                with col3:

                    st.metric(
                        "LOW Risk",
                        low_count
                    )


                # =================================================
                # INDIVIDUAL THREAT REPORTS
                # =================================================

                st.markdown(
                    "### Account Threat Reports"
                )


                for _, report in risk_report.iterrows():

                    user_id = report["user_id"]

                    score = report["risk_score"]

                    level = report["risk_level"]


                    with st.expander(
                        f"User {user_id} — "
                        f"{level} Risk — "
                        f"{score}/100"
                    ):

                        st.write(
                            f"**User ID:** {user_id}"
                        )

                        st.write(
                            f"**Risk Score:** "
                            f"{score}/100"
                        )

                        st.write(
                            f"**Risk Level:** "
                            f"{level}"
                        )

                        st.write(
                            f"**Detectors Triggered:** "
                            f"{report['detector_count']}"
                        )


                        st.markdown(
                            "**Indicators:**"
                        )

                        for detector in str(
                            report[
                                "detectors_triggered"
                            ]
                        ).split(", "):

                            st.write(
                                f"• {detector}"
                            )


                        st.markdown(
                            "**Evidence:**"
                        )

                        for reason in str(
                            report["reasons"]
                        ).split(" | "):

                            st.write(
                                f"• {reason}"
                            )


            # =================================================
            # RAW DETECTION DETAILS
            # =================================================

            with st.expander(
                "View Combined Detection Evidence"
            ):

                if detection_details.empty:

                    st.write(
                        "No detection evidence available."
                    )

                else:

                    st.dataframe(
                        detection_details,
                        use_container_width=True
                    )


            # =================================================
            # FINAL STATUS
            # =================================================

            st.markdown("---")

            st.markdown(
                "## Final CyberGuard Status"
            )


            total_detections = (
                len(failed_login_results)
                + len(password_spraying_results)
                + len(unusual_location_results)
                + len(unknown_device_results)
                + len(suspicious_session_results)
                + len(behaviour_change_results)
            )


            if total_detections > 0:

                st.error(
                    "⚠️ Suspicious account activity detected."
                )

                st.write(
                    f"CyberGuard identified "
                    f"{total_detections} detection event(s) "
                    "across the six account-takeover detectors."
                )

            else:

                st.success(
                    "✅ No suspicious account activity detected."
                )


    except Exception as e:

        st.error(
            "An error occurred while analysing "
            "the datasets."
        )

        st.code(
            str(e)
        )


# ============================================================
# WAITING STATE
# ============================================================

else:

    st.info(
        "Upload both CSV files to begin "
        "account takeover analysis."
    )

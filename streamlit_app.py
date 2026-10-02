import streamlit as st
import pandas as pd

from account_takeover_engine import (
    detect_multiple_failed_logins,
    detect_password_spraying,
    detect_unusual_locations,
    detect_unknown_devices,
    detect_suspicious_sessions
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

            if "is_anomaly" in events.columns:

                suspicious_events = int(
                    events["is_anomaly"].sum()
                )

            else:

                suspicious_events = 0

            st.metric(
                "Suspicious Events",
                suspicious_events
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
            # DETECTION SUMMARY
            # =================================================

            st.markdown(
                "## Detection Summary"
            )


            failed_count = len(
                failed_login_results
            )

            spraying_count = len(
                password_spraying_results
            )

            location_count = len(
                unusual_location_results
            )

            device_count = len(
                unknown_device_results
            )

            session_count = len(
                suspicious_session_results
            )


            summary_col1, summary_col2, summary_col3 = (
                st.columns(3)
            )


            with summary_col1:

                st.metric(
                    "Multiple Failed Logins",
                    failed_count
                )

                st.metric(
                    "Password Spraying",
                    spraying_count
                )


            with summary_col2:

                st.metric(
                    "Unusual Locations",
                    location_count
                )

                st.metric(
                    "Unknown Devices",
                    device_count
                )


            with summary_col3:

                st.metric(
                    "Suspicious Sessions",
                    session_count
                )


            # =================================================
            # OVERALL STATUS
            # =================================================

            st.markdown(
                "## Overall Status"
            )


            total_detections = (
                failed_count
                + spraying_count
                + location_count
                + device_count
                + session_count
            )


            if total_detections > 0:

                st.error(
                    "⚠️ Suspicious account activity detected."
                )

                st.write(
                    "CyberGuard identified one or more "
                    "account-takeover indicators."
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

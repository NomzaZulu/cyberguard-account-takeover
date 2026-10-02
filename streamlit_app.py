import streamlit as st
import pandas as pd

from account_takeover_engine import (
    detect_multiple_failed_logins,
    detect_password_spraying
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
    "Upload organisation profile data and login activity "
    "to analyse suspicious account behaviour."
)


# ============================================================
# FILE UPLOAD SECTION
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
# ANALYSIS
# ============================================================

if profiles_file is not None and events_file is not None:

    try:

        # ----------------------------------------------------
        # LOAD DATA
        # ----------------------------------------------------

        profiles = pd.read_csv(profiles_file)

        events = pd.read_csv(events_file)


        # ----------------------------------------------------
        # SUCCESS MESSAGE
        # ----------------------------------------------------

        st.success(
            "Both datasets uploaded successfully."
        )


        # ----------------------------------------------------
        # DATASET METRICS
        # ----------------------------------------------------

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

            suspicious_events = (
                events["is_anomaly"].sum()
                if "is_anomaly" in events.columns
                else 0
            )

            st.metric(
                "Suspicious Events",
                int(suspicious_events)
            )


        # ----------------------------------------------------
        # DATA PREVIEW
        # ----------------------------------------------------

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
        # DETECTION BUTTON
        # ====================================================

        st.markdown("## Account Takeover Analysis")


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
                detect_multiple_failed_logins(events)
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
                detect_password_spraying(events)
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
            # SUMMARY
            # =================================================

            st.markdown("## Detection Summary")


            failed_count = len(
                failed_login_results
            )

            spraying_count = len(
                password_spraying_results
            )


            summary_col1, summary_col2 = st.columns(2)


            with summary_col1:

                st.metric(
                    "Multiple Failed Login Detections",
                    failed_count
                )


            with summary_col2:

                st.metric(
                    "Password Spraying Detections",
                    spraying_count
                )


            # =================================================
            # OVERALL STATUS
            # =================================================

            st.markdown("## Overall Status")


            if failed_count > 0 or spraying_count > 0:

                st.error(
                    "⚠️ Suspicious account activity detected."
                )

                st.write(
                    "CyberGuard identified behaviour that "
                    "matches known credential attack patterns."
                )

            else:

                st.success(
                    "✅ No credential attack patterns detected."
                )


    except Exception as e:

        st.error(
            "An error occurred while analysing the datasets."
        )

        st.code(
            str(e)
        )


# ============================================================
# WAITING STATE
# ============================================================

else:

    st.info(
        "Upload both CSV files to begin account takeover analysis."
    )

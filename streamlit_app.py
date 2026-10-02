import streamlit as st
import pandas as pd

from account_takeover_engine import detect_multiple_failed_logins


st.set_page_config(
    page_title="CyberGuard - Account Takeover",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ CyberGuard")
st.subheader("Credential Theft & Account Takeover Detection")

st.write(
    "Upload the organisation profile and login event datasets "
    "to test CyberGuard's account takeover detection engine."
)


# ============================================================
# FILE UPLOADS
# ============================================================

st.markdown("### 1. Upload Organisation Profiles")

profiles_file = st.file_uploader(
    "Upload organisation profiles CSV",
    type=["csv"],
    key="profiles"
)


st.markdown("### 2. Upload Login Events")

events_file = st.file_uploader(
    "Upload login events CSV",
    type=["csv"],
    key="events"
)


# ============================================================
# RUN DETECTION
# ============================================================

if profiles_file is not None and events_file is not None:

    profiles = pd.read_csv(profiles_file)
    events = pd.read_csv(events_file)

    st.success("Both datasets uploaded successfully.")

    col1, col2 = st.columns(2)

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

    st.markdown("### Dataset Preview")

    with st.expander("Organisation Profiles"):
        st.dataframe(
            profiles,
            use_container_width=True
        )

    with st.expander("Login Events"):
        st.dataframe(
            events.head(100),
            use_container_width=True
        )

    st.markdown("### 3. Run Detection")

    if st.button(
        "🔍 Detect Account Takeover Activity",
        use_container_width=True
    ):

        try:

            detections = detect_multiple_failed_logins(events)

            st.markdown("## Detection Results")

            if detections.empty:

                st.info(
                    "No multiple failed-login attacks detected."
                )

            else:

                st.warning(
                    f"{len(detections)} suspicious user(s) detected."
                )

                st.dataframe(
                    detections,
                    use_container_width=True
                )

                st.markdown("### Detected Threats")

                for _, row in detections.iterrows():

                    st.error(
                        f"""
                        **User:** {row['user_id']}

                        **Threat:** {row['threat']}

                        **Failed Attempts:** {row['failed_attempts']}

                        **Risk:** {row['risk']}
                        """
                    )

        except Exception as e:

            st.error(
                f"Detection failed: {str(e)}"
            )

else:

    st.info(
        "Upload both CSV files to start the detection."
    )

from fastapi import FastAPI, HTTPException, UploadFile, File
import pandas as pd
import io

from account_takeover_service import (
    analyze_account_takeover
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CyberGuard Account Takeover API",
    description="Account Takeover Detection API",
    version="1.0.0"
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "status": "online",
        "service": "CyberGuard Account Takeover Detection API",
        "version": "1.0.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# ACCOUNT TAKEOVER ANALYSIS
# ============================================================

@app.post("/analyze/account-takeover")
async def analyze_account_takeover_api(
    events_file: UploadFile = File(...),
    profiles_file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate file types
    # --------------------------------------------------------

    if not events_file.filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="Events file must be a CSV file."
        )


    if not profiles_file.filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="Profiles file must be a CSV file."
        )


    try:

        # ----------------------------------------------------
        # Read uploaded files
        # ----------------------------------------------------

        events_bytes = await events_file.read()

        profiles_bytes = await profiles_file.read()


        events = pd.read_csv(
            io.BytesIO(events_bytes)
        )


        profiles = pd.read_csv(
            io.BytesIO(profiles_bytes)
        )


        # ----------------------------------------------------
        # Run Account Takeover Service
        # ----------------------------------------------------

        result = analyze_account_takeover(
            events,
            profiles
        )


        # ----------------------------------------------------
        # Return structured JSON
        # ----------------------------------------------------

        return result


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

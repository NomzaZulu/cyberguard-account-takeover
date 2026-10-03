from fastapi import FastAPI, HTTPException, UploadFile, File
import pandas as pd
import io

from account_takeover_service import analyze_account_takeover


# ============================================================
# CYBERGUARD ACCOUNT TAKEOVER API
# ============================================================

app = FastAPI(
    title="CyberGuard Account Takeover API",
    description="Credential Theft & Account Takeover Detection API",
    version="1.0.0"
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "status": "online",
        "service": "CyberGuard Account Takeover Detection",
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
    # Validate uploaded files
    # --------------------------------------------------------

    if not events_file.filename:

        raise HTTPException(
            status_code=400,
            detail="Login events file was not provided."
        )


    if not profiles_file.filename:

        raise HTTPException(
            status_code=400,
            detail="User profiles file was not provided."
        )


    if not events_file.filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="Login events file must be a CSV file."
        )


    if not profiles_file.filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="User profiles file must be a CSV file."
        )


    try:

        # ----------------------------------------------------
        # Read uploaded files
        # ----------------------------------------------------

        events_bytes = await events_file.read()

        profiles_bytes = await profiles_file.read()


        if not events_bytes:

            raise HTTPException(
                status_code=400,
                detail="Login events CSV is empty."
            )


        if not profiles_bytes:

            raise HTTPException(
                status_code=400,
                detail="User profiles CSV is empty."
            )


        # ----------------------------------------------------
        # Convert CSV → DataFrame
        # ----------------------------------------------------

        events = pd.read_csv(
            io.BytesIO(events_bytes)
        )


        profiles = pd.read_csv(
            io.BytesIO(profiles_bytes)
        )


        # ----------------------------------------------------
        # Validate basic structure
        # ----------------------------------------------------

        if events.empty:

            raise HTTPException(
                status_code=400,
                detail="Login events CSV contains no records."
            )


        if profiles.empty:

            raise HTTPException(
                status_code=400,
                detail="User profiles CSV contains no records."
            )


        # ----------------------------------------------------
        # Run complete Account Takeover pipeline
        # ----------------------------------------------------

        result = analyze_account_takeover(
            events,
            profiles
        )


        # ----------------------------------------------------
        # Return structured result
        # ----------------------------------------------------

        return result


    except HTTPException:

        raise


    except pd.errors.EmptyDataError:

        raise HTTPException(
            status_code=400,
            detail="One of the uploaded CSV files is empty or invalid."
        )


    except pd.errors.ParserError:

        raise HTTPException(
            status_code=400,
            detail="Unable to parse one of the uploaded CSV files."
        )


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Account takeover analysis failed: {str(e)}"
        )

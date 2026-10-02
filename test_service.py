import pandas as pd

from account_takeover_service import (
    analyze_account_takeover
)


# ============================================================
# LOAD YOUR TEST CSV
# ============================================================

events = pd.read_csv(
    "login_events.csv"
)

profiles = pd.read_csv(
    "user_profiles.csv"
)


# ============================================================
# RUN ACCOUNT TAKEOVER ANALYSIS
# ============================================================

result = analyze_account_takeover(
    events,
    profiles
)


# ============================================================
# PRINT SUMMARY
# ============================================================

print("\n==============================")
print("ACCOUNT TAKEOVER TEST")
print("==============================")

print(
    "\nSUMMARY:"
)

print(
    result["summary"]
)


# ============================================================
# PRINT FIRST 5 ACCOUNTS
# ============================================================

print(
    "\nTOP ACCOUNTS:"
)

for account in result["accounts"][:5]:

    print(
        "\nUser:",
        account.get("user_id")
    )

    print(
        "Risk:",
        account.get("risk_level")
    )

    print(
        "Score:",
        account.get("risk_score")
    )

    print(
        "Detectors:",
        account.get(
            "detectors_triggered"
        )
    )

    print(
        "Reasons:",
        account.get(
            "reasons"
        )
    )


print(
    "\n=============================="
)
print(
    "SERVICE TEST COMPLETE"
)
print(
    "=============================="
)

import sys
import os
import traceback
from datetime import datetime

sys.path.append(os.path.dirname(__file__))

from scanner import run_scan
from backend.cloudmapper.pipeline import run_cloudmapper_pipeline


AWS_ACCOUNT_NAME = os.getenv("AWS_ACCOUNT_NAME", "default")


def main():
    print("⏰ Scheduled scan started at", datetime.utcnow())

    try:
        # 1️⃣ Build asset inventory first
        print("🧱 Running CloudMapper inventory scan")
        run_cloudmapper_pipeline(account=AWS_ACCOUNT_NAME)

        # 2️⃣ Run existing vulnerability scanners
        print("🔍 Running vulnerability scanners")
        run_scan()

        print("✅ Scheduled scan completed successfully")

    except Exception:
        print("❌ Scheduled scan failed")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

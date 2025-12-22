import sys
import os
import traceback
from datetime import datetime

sys.path.append(os.path.dirname(__file__))

from scanner import run_scan


def main():
    print("⏰ Scheduled scan started at", datetime.utcnow())

    try:
        run_scan()
        print("✅ Scheduled scan completed successfully")
    except Exception:
        print("❌ Scheduled scan failed")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

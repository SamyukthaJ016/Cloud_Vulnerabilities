from datetime import datetime
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")


def run_scan():
    print("🔍 Running scanner logic")

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # Simple test insert to confirm wiring
    cur.execute("""
        INSERT INTO scans (account_id, cloud, status, started_at)
        VALUES (%s, %s, %s, %s)
        RETURNING id;
    """, (
        "test-account",
        "aws",
        "completed",
        datetime.utcnow()
    ))

    scan_id = cur.fetchone()[0]
    conn.commit()

    cur.close()
    conn.close()

    print(f"✅ Scan inserted with ID {scan_id}")

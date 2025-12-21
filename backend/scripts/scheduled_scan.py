import os
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

def run_scan():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()

    # 1️⃣ Insert scan
    cur.execute("""
        INSERT INTO scans (account_id, cloud, status, started_at, completed_at)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
    """, (
        "test-account",
        "aws",
        "completed",
        datetime.utcnow(),
        datetime.utcnow()
    ))

    scan_id = cur.fetchone()[0]
    print(f"✅ Scan inserted: {scan_id}")

    # 2️⃣ Insert resource
    cur.execute("""
        INSERT INTO resources (scan_id, cloud, type, name, public)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
    """, (
        scan_id,
        "aws",
        "s3_bucket",
        "test-bucket",
        True
    ))

    resource_id = cur.fetchone()[0]
    print(f"✅ Resource inserted: {resource_id}")

    # 3️⃣ Insert vulnerability
    cur.execute("""
        INSERT INTO vulnerabilities
        (scan_id, resource_id, vuln_id, title, severity, cvss_score, tool)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """, (
        scan_id,
        resource_id,
        "CVE-TEST-1234",
        "Test vulnerability",
        "HIGH",
        8.2,
        "manual-test"
    ))

    conn.commit()
    cur.close()
    conn.close()

    print("🎉 Scan + vulnerability stored in DB")

if __name__ == "__main__":
    run_scan()

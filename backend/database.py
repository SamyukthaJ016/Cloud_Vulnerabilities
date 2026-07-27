"""
Fixed database.py - Connection Handling
Add this to your backend/database.py
"""
import os
import json
import psycopg2
import logging
from datetime import datetime, date
from dotenv import load_dotenv
from typing import List, Dict, Any

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("database")

# -------------------------------------------------------------------
# Database Connection (FIXED)
# -------------------------------------------------------------------
_DB_CONN = None


def get_conn():
    """
    Get a valid database connection.
    Always returns a live connection or raises.
    """
    global _DB_CONN

    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        logger.critical("❌ DATABASE_URL not set")
        raise RuntimeError("DATABASE_URL not set")

    try:
        if _DB_CONN is None or _DB_CONN.closed:
            logger.info("Connecting to database...")
            _DB_CONN = psycopg2.connect(db_url)
            _DB_CONN.autocommit = True   # 🔁 yahan True karo
            logger.info("✅ Database connected")


        return _DB_CONN

    except psycopg2.OperationalError as e:
        logger.critical(f"❌ Database connection failed: {e}")
        raise


def ensure_connection():
    """Ensure we have a valid connection, create if needed"""
    conn = get_conn()
    if conn is None:
        raise RuntimeError("Failed to establish database connection")
    return conn


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


# -------------------------------------------------------------------
# Scans
# -------------------------------------------------------------------
def create_scan_record(account_id, cloud, aws_credential_id=None):
    conn = ensure_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO scans (account_id, cloud, status, aws_credential_id)
            VALUES (%s, %s, 'running', %s)
            RETURNING id
            """,
            (account_id, cloud, aws_credential_id),
        )
        scan_id = cur.fetchone()[0]
        conn.commit()
        logger.info(f"Created scan record: {scan_id} (aws_cred_id={aws_credential_id})")
        return scan_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to create scan record: {e}")
        raise
    finally:
        cur.close()


def finish_scan_record(scan_id: int, status: str = "completed") -> None:
    conn = ensure_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE scans
            SET
                status = %s,
                completed_at = NOW(),
                duration_seconds = COALESCE(
                    duration_seconds,
                    GREATEST(0, EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER)
                )
            WHERE id = %s
            """,
            (status, scan_id),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to finish scan record {scan_id}: {e}")
        raise
    finally:
        cur.close()


# -------------------------------------------------------------------
# Resources
# -------------------------------------------------------------------
def store_resource(scan_id, cloud, resource_type, name, config, is_public):
    conn = ensure_connection()  # CHANGED: Use ensure_connection
    cur = conn.cursor()
    try:
        config_json = json.dumps(config, default=json_serial)
        cur.execute(
            """
            INSERT INTO resources (scan_id, cloud, type, name, config, public)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (scan_id, cloud, resource_type, name, config_json, is_public),
        )
        rid = cur.fetchone()[0]
        conn.commit()
        return rid
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to store resource: {e}")
        raise
    finally:
        cur.close()


# -------------------------------------------------------------------
# Findings
# -------------------------------------------------------------------
def store_finding(scan_id, resource_id, severity, description, source):
    conn = ensure_connection()  # CHANGED: Use ensure_connection
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO findings
            (scan_id, resource_id, severity, description, validated_by)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (scan_id, resource_id, severity, description[:5000], source),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to store finding: {e}")
        raise
    finally:
        cur.close()


# -------------------------------------------------------------------
# Vulnerabilities (ADDED - This was missing!)
# -------------------------------------------------------------------
def store_vulnerability(scan_id: int, resource_id: int, vuln_data: Dict[str, Any]) -> int:
    """Store vulnerability finding"""
    conn = ensure_connection()  # CHANGED: Use ensure_connection
    cur = conn.cursor()

    refs = vuln_data.get("references", [])
    refs_json = json.dumps(refs if isinstance(refs, list) else [])

    try:
        cur.execute(
            """
            INSERT INTO vulnerabilities
            (scan_id, resource_id, vuln_id, title, severity, description,
             affected_package, fixed_version, cvss_score, tool, reference_urls)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (
                scan_id,
                resource_id,
                vuln_data.get("vuln_id", "UNKNOWN"),
                vuln_data.get("title", "Unknown")[:500],
                vuln_data.get("severity", "MEDIUM"),
                vuln_data.get("description", "")[:5000],
                vuln_data.get("affected_package"),
                vuln_data.get("fixed_version"),
                vuln_data.get("cvss_score"),
                vuln_data.get("tool", "unknown")[:50],
                refs_json,
            ),
        )
        vid = cur.fetchone()[0]
        conn.commit()
        logger.info(f"Stored vulnerability: {vid}")
        return vid
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to store vulnerability: {e}")
        raise
    finally:
        cur.close()


# -------------------------------------------------------------------
# Reporting
# -------------------------------------------------------------------
def get_scan_report(scan_id):
    conn = ensure_connection()  # CHANGED: Use ensure_connection
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT r.id, r.name, r.cloud, r.type, r.public,
                   f.severity, f.description
            FROM resources r
            LEFT JOIN findings f ON r.id = f.resource_id
            WHERE r.scan_id = %s
            ORDER BY r.id
            """,
            (scan_id,),
        )
        rows = cur.fetchall()
        return rows
    finally:
        cur.close()


def get_multi_cloud_summary(scan_ids=None):
    conn = ensure_connection()
    cur = conn.cursor()
    try:
        query = """
            SELECT
                r.cloud,
                COUNT(DISTINCT r.id),
                COUNT(DISTINCT f.id),
                COUNT(DISTINCT CASE WHEN r.public THEN r.id END)
            FROM resources r
            LEFT JOIN findings f ON r.id = f.resource_id
        """
        params = []
        if scan_ids:
            try:
                ids = [int(i.strip()) for i in scan_ids.split(",")]
                query += " WHERE r.scan_id = ANY(%s)"
                params.append(ids)
            except ValueError:
                pass
        
        query += " GROUP BY r.cloud"
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        return rows
    finally:
        cur.close()


def get_latest_scans(limit=5):
    conn = ensure_connection()  # CHANGED: Use ensure_connection
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, account_id, cloud, status, started_at
            FROM scans
            ORDER BY started_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return rows
    finally:
        cur.close()


# -------------------------------------------------------------------
# Vulnerability Queries
# -------------------------------------------------------------------
def get_vulnerabilities_by_scan(scan_id: int) -> List[Dict[str, Any]]:
    """
    Get all vulnerabilities for a given scan
    """
    conn = ensure_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                v.id,
                v.vuln_id,
                v.title,
                v.severity,
                v.description,
                v.affected_package,
                v.fixed_version,
                v.cvss_score,
                v.tool,
                v.reference_urls,
                v.created_at,
                r.name AS resource_name,
                r.cloud AS provider,
                r.type AS resource_type
            FROM vulnerabilities v
            JOIN resources r ON v.resource_id = r.id
            WHERE v.scan_id = %s
            ORDER BY
                CASE v.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                v.created_at DESC
            """,
            (scan_id,),
        )

        rows = cur.fetchall()

        return [
            {
                "id": row[0],
                "vuln_id": row[1],
                "title": row[2],
                "severity": row[3],
                "description": row[4],
                "affected_package": row[5],
                "fixed_version": row[6],
                "cvss_score": row[7],
                "tool": row[8],
                "references": json.loads(row[9]) if row[9] else [],
                "created_at": row[10].isoformat() if row[10] else None,
                "resource_name": row[11],
                "provider": row[12],
                "resource_type": row[13],
            }
            for row in rows
        ]

    finally:
        cur.close()

def get_vulnerability_summary(scan_id: int | None = None) -> Dict[str, Any]:
    """
    Get vulnerability summary statistics.
    If scan_id is provided, scope to that scan.
    """
    conn = ensure_connection()
    cur = conn.cursor()

    try:
        if scan_id:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                    COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
                    COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium,
                    COUNT(*) FILTER (WHERE severity = 'LOW') AS low,
                    COUNT(DISTINCT tool) AS tools_used
                FROM vulnerabilities
                WHERE scan_id = %s
                """,
                (scan_id,),
            )
        else:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                    COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
                    COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium,
                    COUNT(*) FILTER (WHERE severity = 'LOW') AS low,
                    COUNT(DISTINCT tool) AS tools_used
                FROM vulnerabilities
                """
            )

        row = cur.fetchone()

        return {
            "total": row[0],
            "critical": row[1],
            "high": row[2],
            "medium": row[3],
            "low": row[4],
            "tools_used": row[5],
        }

    finally:
        cur.close()


# -------------------------------------------------------------------
# Health Check
# -------------------------------------------------------------------
def check_database_health():
    """Check if database is accessible"""
    try:
        conn = get_conn()
        if conn is None:
            return False
        
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return True
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False


print("✅ Multi-Cloud Database Module Loaded (STABLE)")

# -------------------------------------------------------------------
# CloudFox Helper (ADD ONLY – NO EXISTING CODE TOUCHED)
# -------------------------------------------------------------------
def store_cloudfox_finding(
    scan_id: int,
    resource_name: str,
    resource_type: str,
    cloud: str,
    severity: str,
    description: str
):
    """
    Helper to store CloudFox findings using existing tables.
    """
    # 1. Store resource (CloudFox findings are IAM-level, so not public)
    resource_id = store_resource(
        scan_id=scan_id,
        cloud=cloud,
        resource_type=resource_type,
        name=resource_name,
        config={"source": "cloudfox"},
        is_public=False
    )

    # 2. Store finding
    store_finding(
        scan_id=scan_id,
        resource_id=resource_id,
        severity=severity,
        description=description,
        source="cloudfox"
    )

import os
import json
import psycopg2
from datetime import datetime, date
from dotenv import load_dotenv

load_dotenv()
DB_CONN = psycopg2.connect(os.getenv("DATABASE_URL"))


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def create_scan_record(account_id, cloud):
    """Create scan record and return ID"""
    cur = DB_CONN.cursor()
    cur.execute(
        "INSERT INTO scans (account_id, cloud, status) VALUES (%s, %s, 'running') RETURNING id",
        (account_id, cloud),
    )
    scan_id = cur.fetchone()[0]
    DB_CONN.commit()
    cur.close()
    return scan_id


def store_resource(scan_id, cloud, resource_type, name, config, is_public):
    """Store resource and return resource_id"""
    cur = DB_CONN.cursor()
    
    # Serialize config with datetime support
    config_json = json.dumps(config, default=json_serial)
    
    cur.execute(
        """INSERT INTO resources (scan_id, cloud, type, name, config, public) 
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
        (scan_id, cloud, resource_type, name, config_json, is_public),
    )
    resource_id = cur.fetchone()[0]
    DB_CONN.commit()
    cur.close()
    return resource_id


def store_finding(scan_id, resource_id, severity, description, source):
    """Store security finding"""
    cur = DB_CONN.cursor()
    cur.execute(
        "INSERT INTO findings (scan_id, resource_id, severity, description, validated_by) VALUES (%s, %s, %s, %s, %s)",
        (scan_id, resource_id, severity, description, source),
    )
    DB_CONN.commit()
    cur.close()


def get_scan_report(scan_id):
    """Get complete scan report"""
    cur = DB_CONN.cursor()
    cur.execute(
        """
        SELECT r.id, r.name, r.cloud, r.type, r.public, f.severity, f.description 
        FROM resources r 
        LEFT JOIN findings f ON r.id = f.resource_id 
        WHERE r.scan_id = %s 
        ORDER BY r.id
    """,
        (scan_id,),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


# MULTI-CLOUD SPECIALIZED FUNCTIONS
def store_aws_s3_bucket(scan_id, bucket_name, policy, is_public):
    """Store AWS S3 bucket"""
    return store_resource(scan_id, "aws", "s3_bucket", bucket_name, policy, is_public)


def store_gcp_gcs_bucket(scan_id, bucket_name, policy, is_public):
    """Store GCP Cloud Storage bucket"""
    return store_resource(scan_id, "gcp", "gcs_bucket", bucket_name, policy, is_public)


def store_openai_resource(scan_id, resource_type, name, details, is_public=False):
    """Store OpenAI resource (models, usage, etc.)"""
    return store_resource(scan_id, "openai", resource_type, name, details, is_public)


def get_multi_cloud_summary():
    """Get summary across all clouds"""
    cur = DB_CONN.cursor()
    cur.execute(
        """
        SELECT cloud, COUNT(*) as resources, 
               COUNT(f.id) as findings,
               COUNT(CASE WHEN r.public = true THEN 1 END) as public_resources
        FROM resources r 
        LEFT JOIN findings f ON r.id = f.resource_id 
        GROUP BY cloud 
        ORDER BY resources DESC
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def get_latest_scans(limit=5):
    """Get most recent scans"""
    cur = DB_CONN.cursor()
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
    cur.close()
    return rows


def get_cloud_posture_by_scan(scan_id):
    """Detailed posture report per scan"""
    cur = DB_CONN.cursor()
    cur.execute(
        """
        SELECT r.cloud, r.type, r.name, r.public, f.severity, f.description
        FROM resources r 
        LEFT JOIN findings f ON r.id = f.resource_id 
        WHERE r.scan_id = %s
        ORDER BY r.cloud, r.type
    """,
        (scan_id,),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


print("Multi-Cloud Database Module Loaded")
"""Session leases release automatically if a cleanup worker crashes."""

import os
from contextlib import contextmanager
import psycopg2


@contextmanager
def sandbox_cleanup_lease(lab_id: str):
    # Use a dedicated connection: a process-wide connection would make advisory
    # locks reentrant across concurrent cleanup requests.
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))", ("sandbox-cleanup:" + lab_id,))
            yield bool(cur.fetchone()[0])
    finally:
        conn.close()

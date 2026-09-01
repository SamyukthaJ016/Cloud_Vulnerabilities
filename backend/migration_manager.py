import os
import logging
import psycopg2
from pathlib import Path

logger = logging.getLogger("migration_manager")

def run_migrations():
    """
    Finds all .sql files in /app/db/init and runs them in order.
    Tracking is done via a dedicated 'migrations_applied' table.
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        logger.error("DATABASE_URL not set, skipping migrations")
        return

    # In Docker, we'll mount it to /app/db/init
    # Local fallback for development outside Docker
    migration_dir = Path("/app/db/init")
    if not migration_dir.exists():
        migration_dir = Path(__file__).parent.parent / "db" / "init"

    if not migration_dir.exists():
        logger.warning(f"Migration directory {migration_dir} not found")
        return

    logger.info(f"Checking for migrations in {migration_dir}...")

    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()

        # 1. Ensure tracking table exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS migration_history (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) UNIQUE NOT NULL,
                applied_at TIMESTAMP DEFAULT NOW()
            );
        """)

        # 2. Get applied migrations
        cur.execute("SELECT filename FROM migration_history")
        applied_files = {row[0] for row in cur.fetchall()}

        # 3. Find and sort migration files
        sql_files = sorted([f for f in migration_dir.glob("*.sql")])

        for sql_file in sql_files:
            filename = sql_file.name
            if filename in applied_files:
                continue

            logger.info("Applying migration: %s", filename)
            try:
                with open(sql_file, "r") as f:
                    sql_content = f.read()
                    if sql_content.strip():
                        cur.execute(sql_content)
                
                # Record success
                cur.execute("INSERT INTO migration_history (filename) VALUES (%s)", (filename,))
                logger.info("Migration applied: %s", filename)
            except Exception as e:
                logger.exception("Failed migration %s", filename)
                raise RuntimeError(f"Migration {filename} failed") from e

        cur.close()
        conn.close()
    except Exception:
        logger.exception("Failed to run database migrations")
        raise

if __name__ == "__main__":
    # Allow running as a standalone script
    logging.basicConfig(level=logging.INFO)
    run_migrations()

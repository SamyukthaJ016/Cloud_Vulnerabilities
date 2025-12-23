# backend/scheduler_worker.py
import asyncio
import json
import logging

from backend.database import get_conn
from backend.main import run_multi_cloud_scan_internal  # helper from main.py

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scheduler")


async def run_due_schedules():
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, user_id, providers, account_ids, deep_scan, schedule
            FROM scan_schedules
            WHERE status = 'scheduled' AND next_run_at <= NOW()
            FOR UPDATE SKIP LOCKED
            """
        )
        rows = cur.fetchall()

    if not rows:
        logger.info("🕒 No due schedules found")
        return

    logger.info(f"🕒 Found {len(rows)} due scheduled scans")

    for row in rows:
        schedule_id, user_id, providers_text, account_ids_text, deep_scan, schedule = row
        providers = json.loads(providers_text)
        account_ids = json.loads(account_ids_text)

        logger.info(f"▶️ Running scheduled scan {schedule_id} for user={user_id} providers={providers}")

        try:
            result_ctx = await run_multi_cloud_scan_internal(
                providers=providers,
                account_ids=account_ids,
                deep_scan=deep_scan,
                user_id=user_id or "anonymous",
            )
            scan_ids = result_ctx["scan_ids"]

            conn = get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_schedules
                    SET status = 'completed',
                        schedule = jsonb_set(
                            schedule,
                            '{last_run_scan_ids}',
                            to_jsonb(%s::text[]),
                            true
                        )
                    WHERE id = %s
                    """,
                    (scan_ids, schedule_id),
                )
                conn.commit()

            logger.info(f"✅ Scheduled scan {schedule_id} completed, scan_ids={scan_ids}")

        except Exception as e:
            logger.error(f"❌ Scheduled scan {schedule_id} failed: {e}")
            conn = get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_schedules
                    SET status = 'failed',
                        schedule = jsonb_set(
                            schedule,
                            '{last_error}',
                            to_jsonb(%s::text),
                            true
                        )
                    WHERE id = %s
                    """,
                    (str(e), schedule_id),
                )
                conn.commit()


async def main_loop():
    logger.info("🚀 Scheduler worker started")
    while True:
        try:
            await run_due_schedules()
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}")
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main_loop())

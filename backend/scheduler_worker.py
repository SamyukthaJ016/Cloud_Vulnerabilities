# backend/scheduler_worker.py
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from backend.database import get_conn
from backend.main import run_multi_cloud_scan_internal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scheduler")


async def run_due_schedules():
    """Run all scheduled scans that are due"""
    conn = get_conn()
    
    try:
        with conn.cursor() as cur:
            # Get all due schedules with FOR UPDATE SKIP LOCKED to prevent concurrent execution
            cur.execute(
                """
                SELECT id, user_id, providers, account_ids, deep_scan, schedule, credential_id
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
            schedule_id, user_id, providers_text, account_ids_text, deep_scan, schedule, credential_id = row
            
            # Parse JSON fields
            try:
                providers = json.loads(providers_text) if providers_text else []
                account_ids = json.loads(account_ids_text) if account_ids_text else {}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON for schedule {schedule_id}: {e}")
                _mark_schedule_failed(schedule_id, f"JSON parse error: {e}")
                continue

            # Ensure user_id is valid
            if not user_id:
                user_id = "anonymous"
                logger.warning(f"Schedule {schedule_id} has no user_id, using 'anonymous'")

            logger.info(f"▶️ Running scheduled scan {schedule_id} for user={user_id} providers={providers}")

            try:
                # Run the scan using the internal function
                result_ctx = await run_multi_cloud_scan_internal(
                    providers=providers,
                    account_ids=account_ids,
                    deep_scan=deep_scan,
                    user_id=user_id,
                    credential_id=credential_id,  # NEW: Use saved credential
                )
                
                scan_ids = result_ctx.get("scan_ids", [])

                # Update schedule as completed
                with conn.cursor() as cur:
                    # Check if this is a recurring schedule
                    schedule_data = schedule if isinstance(schedule, dict) else {}
                    schedule_type = schedule_data.get("type", "once")
                    
                    if schedule_type == "recurring":
                        # Calculate next run time
                        next_run_at = _calculate_next_run(schedule_data)
                        
                        cur.execute(
                            """
                            UPDATE scan_schedules
                            SET next_run_at = %s,
                                schedule = jsonb_set(
                                    jsonb_set(
                                        schedule,
                                        '{last_run_scan_ids}',
                                        to_jsonb(%s::text[]),
                                        true
                                    ),
                                    '{last_run_at}',
                                    to_jsonb(NOW()::text),
                                    true
                                )
                            WHERE id = %s
                            """,
                            (next_run_at, scan_ids, schedule_id),
                        )
                        logger.info(f"✅ Recurring scan {schedule_id} completed, next run: {next_run_at}")
                    else:
                        # One-time schedule - mark as completed
                        cur.execute(
                            """
                            UPDATE scan_schedules
                            SET status = 'completed',
                            schedule = jsonb_set(
                                jsonb_set(
                                    schedule,
                                        '{last_run_scan_ids}',
                                        to_jsonb(ARRAY[%s]::text[]),
                                        true
                                    ),
                                    '{last_run_at}',
                                    to_jsonb(NOW()::text),
                                    true
                                )
                            WHERE id = %s;

                            """,
                            (scan_ids, schedule_id),
                        )
                        logger.info(f"✅ One-time scan {schedule_id} completed, scan_ids={scan_ids}")
                    
                    conn.commit()

            except Exception as e:
                logger.error(f"❌ Scheduled scan {schedule_id} failed: {e}")
                import traceback
                logger.error(traceback.format_exc())
                _mark_schedule_failed(schedule_id, str(e))

    except Exception as e:
        logger.error(f"Error in run_due_schedules: {e}")
        import traceback
        logger.error(traceback.format_exc())


def _calculate_next_run(schedule_data: dict) -> datetime:
    """Calculate next run time for recurring schedules"""
    try:
        time_str = schedule_data.get("time", "00:00")  # HH:MM
        tz_name = schedule_data.get("timezone", "UTC")
        
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("UTC")
        
        # Get tomorrow in the schedule's timezone
        now_local = datetime.now(tz)
        tomorrow_local = now_local + timedelta(days=1)
        
        # Parse time
        hour, minute = map(int, time_str.split(":"))
        
        # Create next run datetime
        next_run_local = tomorrow_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        # Convert to UTC for storage
        next_run_utc = next_run_local.astimezone(timezone.utc)
        
        return next_run_utc
        
    except Exception as e:
        logger.error(f"Failed to calculate next run time: {e}")
        # Default to 24 hours from now
        return datetime.now(timezone.utc) + timedelta(days=1)


def _mark_schedule_failed(schedule_id: int, error_message: str):
    """Mark a schedule as failed"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_schedules
                SET status = 'failed',
                    schedule = jsonb_set(
                        jsonb_set(
                            schedule,
                            '{last_error}',
                            to_jsonb(%s::text),
                            true
                        ),
                        '{last_error_at}',
                        to_jsonb(%s::text),
                        true
                    )
                WHERE id = %s
                """,
                (error_message, datetime.now(timezone.utc).isoformat(), schedule_id),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to mark schedule as failed: {e}")


async def main_loop():
    """Main scheduler loop"""
    logger.info("🚀 Scheduler worker started")
    
    while True:
        try:
            await run_due_schedules()
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        # Wait 60 seconds before checking again
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main_loop())
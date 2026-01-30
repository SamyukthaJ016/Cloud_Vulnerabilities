# backend/scheduler_worker.py
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from backend.database import get_conn
from backend.main import run_multi_cloud_scan_internal
from backend.utils.email import send_scan_notification

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
                providers = json.loads(providers_text) if isinstance(providers_text, str) else providers_text
                account_ids = json.loads(account_ids_text) if isinstance(account_ids_text, str) else account_ids_text
                schedule_data = json.loads(schedule) if isinstance(schedule, str) else schedule
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
                
                # NEW: Email Notification logic
                with conn.cursor() as cur:
                    cur.execute("SELECT notify_email, email_address FROM scan_schedules WHERE id = %s", (schedule_id,))
                    notify_row = cur.fetchone()
                    if notify_row and notify_row[0]:
                        email = notify_row[1] or f"{user_id}@cloudguard.local"
                        logger.info(f"📧 Notification: Dispatching scan results for {scan_ids} to {email}")
                        send_scan_notification(email, scan_ids)

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
                                        to_jsonb(%s::int[]),
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
                        logger.info(f"✅ Recurring scan {schedule_id} ({schedule_data.get('frequency')}) completed, next run: {next_run_at}")

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
                                        to_jsonb(%s::int[]),
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
                
                # Capture permission error details for CLI commands
                error_details = str(e)
                if hasattr(e, 'iam_user_arn') and hasattr(e, 'recommended_policy_arn'):
                    iam_user_name = e.iam_user_arn.split('/')[-1] if '/' in e.iam_user_arn else e.iam_user_arn
                    
                    # Store as structured JSON in the error message or extra field
                    permission_error = {
                        "type": "permission_required",
                        "iam_user_arn": e.iam_user_arn,
                        "iam_user_name": iam_user_name,
                        "policy_arn": e.recommended_policy_arn,
                        "role_arn": getattr(e, 'role_arn', None),
                        "credential_id": credential_id
                    }
                    error_details = json.dumps(permission_error)

                import traceback
                logger.error(traceback.format_exc())
                _mark_schedule_failed(schedule_id, error_details)

    except Exception as e:
        logger.error(f"Error in run_due_schedules: {e}")
        import traceback
        logger.error(traceback.format_exc())


def _calculate_next_run(schedule_data: dict) -> datetime:
    """Calculate next run time for recurring schedules"""
    try:
        frequency = schedule_data.get("frequency", "daily")
        tz_name = schedule_data.get("timezone", "UTC")
        
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("UTC")
        
        now_local = datetime.now(tz)
        
        # 🏎️ Short Intervals - Calculate from NOW
        if frequency == "10m":
            next_run_local = now_local + timedelta(minutes=10)
        elif frequency == "30m":
            next_run_local = now_local + timedelta(minutes=30)
        elif frequency == "60m" or frequency == "hourly":
            next_run_local = now_local + timedelta(hours=1)
        elif frequency == "6h":
            next_run_local = now_local + timedelta(hours=6)
        
        # 📅 Longer/Fixed Time Intervals
        else:
            time_str = schedule_data.get("time", "00:00")
            hour, minute = map(int, time_str.split(":"))
            
            if frequency == "daily":
                # Next run is tomorrow at the specified time
                next_run_local = (now_local + timedelta(days=1)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            elif frequency == "weekly":
                # Next run is 7 days from now at specified time
                next_run_local = (now_local + timedelta(days=7)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            elif frequency == "2w":
                # Next run is 14 days from now at specified time
                next_run_local = (now_local + timedelta(days=14)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            elif frequency == "monthly":
                # Next run is roughly 30 days from now (simple approach)
                next_run_local = (now_local + timedelta(days=30)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            else:
                # Default fallback: 24h from now
                next_run_local = now_local + timedelta(days=1)

        # Convert to UTC for storage
        next_run_utc = next_run_local.astimezone(timezone.utc)
        logger.info(f"🕒 Calculated next run for frequency='{frequency}': {next_run_utc} (UTC)")
        return next_run_utc
        
    except Exception as e:
        logger.error(f"Failed to calculate next run time: {e}")
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
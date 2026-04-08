import asyncio
import logging

from backend.scheduler_worker import run_due_schedules


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("run_due_schedules_once")


async def _main() -> None:
    logger.info("Starting one-shot scheduled scan sweep")
    await run_due_schedules()
    logger.info("Finished one-shot scheduled scan sweep")


if __name__ == "__main__":
    asyncio.run(_main())

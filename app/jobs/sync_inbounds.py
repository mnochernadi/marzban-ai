"""Scheduled mirror of a remote subscription into the panel's hosts.

Runs every INBOUND_SYNC_INTERVAL seconds (default 30 minutes). Disabled unless
INBOUND_SYNC_ENABLED is set, so an install that does not use the feature is
unaffected.
"""

from app import scheduler
from app.inbound_sync.service import sync_inbounds
from config import INBOUND_SYNC_ENABLED, INBOUND_SYNC_INTERVAL

if INBOUND_SYNC_ENABLED:
    scheduler.add_job(
        sync_inbounds,
        "interval",
        seconds=INBOUND_SYNC_INTERVAL,
        coalesce=True,
        max_instances=1,
    )
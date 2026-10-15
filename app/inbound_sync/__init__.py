"""Mirror a remote share-link subscription into Marzban hosts.

Marzban's inbounds are fixed in xray_config.json, so a mirrored share link is
added as a *host* on the inbound that matches its protocol and transport. The
host carries the upstream server's address and the link's path/SNI/host, which
is what Marzban renders into each user's subscription.
"""

from app.inbound_sync.service import InboundSyncService, sync_inbounds

__all__ = ["InboundSyncService", "sync_inbounds"]
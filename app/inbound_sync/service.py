"""Mirror a remote subscription into Marzban hosts, on a schedule.

Marzban's inbounds are defined in xray_config.json and cannot be created
through its API, but each inbound's *hosts* are database rows the subscription
renderer iterates. So a mirrored share link becomes a host on the inbound whose
protocol and transport match — one host per upstream server — and every user
that has that inbound enabled picks it up.

Hosts this feature owns are tagged with MIRROR_REMARK_PREFIX and replaced on
every refresh; hosts an operator added by hand are never touched.
"""

import logging
from typing import Dict, List, Optional, Tuple

import requests
from sqlalchemy.orm import Session

from app.db import GetDB
from app.db.models import ProxyHost
from app.inbound_sync.parser import ParsedLink, parse_subscription
from app.models.proxy import ProxyTypes
from config import (
    INBOUND_SYNC_ENABLED,
    INBOUND_SYNC_FRONT_HOST,
    INBOUND_SYNC_SUB_URL,
    INBOUND_SYNC_TIMEOUT,
)

logger = logging.getLogger("marzban")

MIRROR_REMARK_PREFIX = "[SYNC] "

# A bases64 subscription of ~100 links is well under this.
MAX_BODY_BYTES = 8 * 1024 * 1024

# Marzban stores the fingerprint as an enum and raises on any value outside it,
# which aborts the whole subscription render. Share links carry values it does
# not know (e.g. "unsafe", "random"), so anything unrecognised falls back to
# "none". The empty string is deliberately not accepted: the ORM maps "none" to
# "" on write and then cannot read its own row back.
VALID_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized",
}


def _safe_fingerprint(fp: Optional[str]) -> str:
    value = (fp or "").strip().lower()
    return value if value in VALID_FINGERPRINTS else "none"


def _front_host() -> str:
    """The domain the operator wants the mirrored servers fronted by."""
    return (INBOUND_SYNC_FRONT_HOST or "").strip()


def _safe_host(link: ParsedLink) -> Optional[str]:
    """The Host header the client sends.

    A share link names the upstream provider's CDN. Serving that verbatim means
    the client asks for a host this panel does not control, and any front
    domain the operator set is ignored. When a front host is configured it wins
    for HTTP-shaped links, which is what makes the links reachable through the
    operator's own proxy.
    """
    front = _front_host()
    if front and link.network in ("ws", "httpupgrade", "xhttp", "splithttp"):
        return front
    return _sanitize_flag(link.host)


def _safe_address(link: ParsedLink) -> str:
    """Where the client connects.

    With a front host configured the server is this panel's own, addressed
    through the same domain — the mirrored link then behaves like a locally
    hosted one, exactly as the equivalent feature does on a panel that can
    create inbounds. Without it, the link keeps pointing at the upstream, so
    the entry is a plain relay of the provider's server.
    """
    return "{SERVER_IP}" if _front_host() else link.address


def _safe_sni(link: ParsedLink) -> Optional[str]:
    """The TLS SNI the client sends; same reasoning as _safe_host."""
    front = _front_host()
    if front and link.security == "tls":
        return front
    return _sanitize_flag(link.sni)


def _sanitize_flag(value: Optional[str]) -> Optional[str]:
    """Marzban treats an empty string as set-but-empty and renders `host=`."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


class SyncResult:
    def __init__(self) -> None:
        self.added = 0
        self.removed = 0
        self.skipped: List[str] = []

    def __repr__(self) -> str:
        return f"added={self.added} removed={self.removed} skipped={len(self.skipped)}"


def _fetch(url: str) -> bytes:
    resp = requests.get(
        url,
        timeout=INBOUND_SYNC_TIMEOUT,
        headers={"User-Agent": "marzban-inbound-sync/1.0"},
    )
    resp.raise_for_status()
    body = resp.content
    if len(body) > MAX_BODY_BYTES:
        raise ValueError(f"subscription body exceeds {MAX_BODY_BYTES} bytes")
    return body


# Marzban identifies an inbound by its tag; the mirror has to pick the inbound
# that already serves the link's protocol and transport. Preference order per
# (protocol, network, security) keeps the choice stable between refreshes.
def _inbound_rank(inbound: dict, link: ParsedLink) -> Tuple[int, int]:
    network = (inbound.get("network") or "tcp").lower()
    security = (inbound.get("tls") or "none").lower()
    network_match = 0 if network == link.network else 1
    security_match = 0 if security == link.security else 1
    return (network_match, security_match)


class InboundSyncService:
    """Fetches the subscription and reconciles mirrored hosts."""

    def __init__(self, session_factory=GetDB) -> None:
        self.session_factory = session_factory

    # ---------------------------------------------------------------- fetch
    def fetch_links(self, url: str) -> List[ParsedLink]:
        return parse_subscription(_fetch(url))

    # ----------------------------------------------------------------- plan
    def build_plan(
        self, links: List[ParsedLink], inbounds: Dict[str, dict], protocols: set
    ) -> Tuple[List[Tuple[str, ParsedLink]], List[str]]:
        """Map each link to the inbound tag it should be mirrored onto."""
        plan: List[Tuple[str, ParsedLink]] = []
        skipped: List[str] = []

        by_protocol: Dict[str, List[dict]] = {}
        for inbound in inbounds.values():
            by_protocol.setdefault(inbound["protocol"], []).append(inbound)

        for link in links:
            if link.protocol not in protocols:
                skipped.append(f"{link.remark}: protocol {link.protocol} not enabled")
                continue
            candidates = by_protocol.get(link.protocol) or []
            if not candidates:
                skipped.append(f"{link.remark}: no {link.protocol} inbound in this panel")
                continue
            best = min(candidates, key=lambda ib: _inbound_rank(ib, link))
            plan.append((best["tag"], link))
        return plan, skipped

    # -------------------------------------------------------------- persist
    def _replace_hosts(
        self, db: Session, tag: str, links: List[ParsedLink]
    ) -> int:
        inbound_hosts = db.query(ProxyHost).filter(ProxyHost.inbound_tag == tag).all()
        removed = 0
        for host in inbound_hosts:
            if (host.remark or "").startswith(MIRROR_REMARK_PREFIX):
                db.delete(host)
                removed += 1
        fronted = bool(_front_host())
        for link in links:
            db.add(
                ProxyHost(
                    inbound_tag=tag,
                    remark=MIRROR_REMARK_PREFIX + link.remark,
                    address=_safe_address(link),
                    # With a front host the server is this panel's own and the
                    # inbound's port is the right one; without it the upstream's
                    # port has to be kept.
                    port=None if fronted else link.port,
                    path=link.path,
                    sni=_safe_sni(link),
                    host=_safe_host(link),
                    security=link.security if link.security in ("none", "tls") else "none",
                    fingerprint=_safe_fingerprint(link.fp),
                    # Passed through the operator's own proxy, the mirrored
                    # entries behave like the panel's own inbounds.
                    allowinsecure=True if fronted else None,
                )
            )
        db.commit()
        return removed

    # --------------------------------------------------------------- public
    def sync(self, url: Optional[str] = None) -> SyncResult:
        """Fetch the subscription and reconcile the mirrored hosts."""
        from app import xray

        url = url or INBOUND_SYNC_SUB_URL
        result = SyncResult()
        if not url:
            raise ValueError("inbound sync URL is not configured")

        links = self.fetch_links(url)
        protocols = {p.value for p in ProxyTypes}

        inbounds = {tag: dict(ib) for tag, ib in xray.config.inbounds_by_tag.items()}
        for tag, inbound in inbounds.items():
            raw = xray.config.get_inbound(tag) or {}
            stream = raw.get("streamSettings") or {}
            inbound.setdefault("network", stream.get("network") or "tcp")
            inbound.setdefault("tls", stream.get("security") or "none")

        plan, skipped = self.build_plan(links, inbounds, protocols)
        result.skipped = skipped

        grouped: Dict[str, List[ParsedLink]] = {}
        for tag, link in plan:
            grouped.setdefault(tag, []).append(link)

        with self.session_factory() as db:
            # Clear mirrored hosts from inbounds that no longer receive any, so
            # a shrinking subscription does not leave stale upstreams behind.
            for tag in inbounds:
                if tag not in grouped:
                    result.removed += self._replace_hosts(db, tag, [])
            for tag, tag_links in grouped.items():
                result.removed += self._replace_hosts(db, tag, tag_links)
                result.added += len(tag_links)

        # The renderer reads hosts from this cache, so it has to be refreshed.
        xray.hosts.update()
        logger.info(
            "inbound sync: fetched %d links, added %d, removed %d, skipped %d",
            len(links), result.added, result.removed, len(result.skipped),
        )
        return result


def sync_inbounds(url: Optional[str] = None) -> Optional[SyncResult]:
    """Scheduled entry point; a failure must not kill the scheduler thread."""
    if not INBOUND_SYNC_ENABLED:
        return None
    try:
        return InboundSyncService().sync(url)
    except Exception as exc:  # noqa: BLE001 - scheduler must survive any error
        logger.error("inbound sync failed: %s", exc)
        return None
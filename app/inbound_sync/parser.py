"""Parse Xray share links (vless/vmess/trojan/ss) into a neutral shape.

Marzban has no share-link parser of its own — it only *emits* links — so the
mirroring feature supplies one. The output is deliberately plain: protocol,
address, port, and the transport fields Marzban's ProxyHost stores.
"""

import base64
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class UnsupportedLink(Exception):
    """The link cannot become a Marzban host (unknown scheme, REALITY, ...)."""


@dataclass
class ParsedLink:
    protocol: str
    address: str
    port: int
    remark: str
    security: str = "none"
    network: str = "tcp"
    path: Optional[str] = None
    host: Optional[str] = None
    sni: Optional[str] = None
    fp: Optional[str] = None
    alpn: Optional[str] = None
    # The credential differs per protocol; kept only to make the identity key
    # stable across refreshes.
    identity: str = ""
    extra: Dict[str, str] = field(default_factory=dict)


def _b64(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def _fragment(url: urllib.parse.SplitResult) -> str:
    return urllib.parse.unquote(url.fragment) or "subscription"


def _security(params: Dict[str, str]) -> str:
    security = (params.get("security") or "none").lower()
    if security == "reality":
        # A share link carries only the REALITY public key; the private key an
        # inbound needs is never distributed, so there is nothing to mirror.
        raise UnsupportedLink("REALITY link carries no private key")
    return security


def parse_vless(link: str) -> ParsedLink:
    u = urllib.parse.urlsplit(link)
    p = dict(urllib.parse.parse_qsl(u.query))
    security = _security(p)
    return ParsedLink(
        protocol="vless",
        address=u.hostname or "",
        port=u.port or 443,
        remark=_fragment(u),
        security=security,
        network=p.get("type") or "tcp",
        path=p.get("path"),
        host=p.get("host"),
        sni=p.get("sni") or p.get("host"),
        fp=p.get("fp"),
        alpn=p.get("alpn"),
        identity=f"vless:{u.username}@{u.hostname}:{u.port}",
    )


def parse_trojan(link: str) -> ParsedLink:
    u = urllib.parse.urlsplit(link)
    p = dict(urllib.parse.parse_qsl(u.query))
    security = p.get("security") or "tls"
    if security == "reality":
        raise UnsupportedLink("REALITY link carries no private key")
    return ParsedLink(
        protocol="trojan",
        address=u.hostname or "",
        port=u.port or 443,
        remark=_fragment(u),
        security=security,
        network=p.get("type") or "tcp",
        path=p.get("path"),
        host=p.get("host"),
        sni=p.get("sni") or p.get("host"),
        fp=p.get("fp"),
        alpn=p.get("alpn"),
        identity=f"trojan:{urllib.parse.unquote(u.username or '')}@{u.hostname}:{u.port}",
    )


def parse_vmess(link: str) -> ParsedLink:
    payload = json.loads(_b64(link[len("vmess://"):]))
    security = "tls" if payload.get("tls") == "tls" else "none"
    return ParsedLink(
        protocol="vmess",
        address=payload.get("add", ""),
        port=int(payload.get("port") or 443),
        remark=payload.get("ps") or "subscription",
        security=security,
        network=payload.get("net") or "tcp",
        path=payload.get("path"),
        host=payload.get("host"),
        sni=payload.get("sni") or payload.get("host"),
        fp=payload.get("fp"),
        alpn=payload.get("alpn"),
        identity=f"vmess:{payload.get('id')}@{payload.get('add')}:{payload.get('port')}",
    )


def parse_shadowsocks(link: str) -> ParsedLink:
    body, _, fragment = link[len("ss://"):].partition("#")
    body = body.split("?", 1)[0]
    userinfo, _, hostport = body.rpartition("@")
    method = ""
    if userinfo:
        try:
            userinfo = _b64(userinfo)
        except ValueError:
            userinfo = urllib.parse.unquote(userinfo)
        method = userinfo.split(":", 1)[0]
    _, _, port = hostport.rpartition(":")
    if not port.isdigit():
        raise UnsupportedLink("shadowsocks link has no port")
    # Shadowsocks credentials live on the inbound in Marzban, so the link only
    # contributes a host entry.
    return ParsedLink(
        protocol="shadowsocks",
        address=hostport.rpartition(":")[0],
        port=int(port),
        remark=urllib.parse.unquote(fragment) or "subscription",
        security="none",
        network="tcp",
        identity=f"ss:{method}@{hostport}",
    )


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
}


def parse_subscription(body: bytes) -> List[ParsedLink]:
    """Parse a subscription body (raw link list, or base64 of one)."""
    text = body.decode("utf-8", "replace").strip()
    if "://" not in text:
        text = _b64(text)
    links: List[ParsedLink] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if "://" not in line:
            continue
        scheme = line.split("://", 1)[0]
        parser = PARSERS.get(scheme)
        if parser is None:
            continue
        try:
            parsed = parser(line)
        except (UnsupportedLink, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if not parsed.address or not 0 < parsed.port < 65536:
            continue
        if parsed.identity in seen:
            continue
        seen.add(parsed.identity)
        links.append(parsed)
    return links
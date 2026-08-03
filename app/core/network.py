import ipaddress
import socket
from urllib.parse import urlsplit


_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


def _reject_private_ip(ip_text: str) -> None:
    ip = ipaddress.ip_address(ip_text)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise ValueError("URL host resolves to a non-public address")


def _validate_public_host(host: str, resolve: bool = True) -> None:
    normalized = host.strip().strip("[]").lower().rstrip(".")
    if not normalized or normalized in _LOCAL_HOSTNAMES or normalized.endswith(".localhost"):
        raise ValueError("URL host is not allowed")

    try:
        _reject_private_ip(normalized)
        return
    except ValueError as exc:
        if "does not appear to be an IPv4 or IPv6 address" not in str(exc):
            raise

    if not resolve:
        return

    try:
        infos = socket.getaddrinfo(normalized, None)
    except socket.gaierror as exc:
        raise ValueError("URL host could not be resolved") from exc
    for info in infos:
        address = info[4][0]
        _reject_private_ip(address)


def validate_public_http_url(url: str, *, allow_http: bool = True, resolve: bool = True) -> str:
    parts = urlsplit(url)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in allowed_schemes:
        raise ValueError("URL must use an allowed HTTP scheme")
    if not parts.hostname:
        raise ValueError("URL must include a hostname")
    if parts.username or parts.password:
        raise ValueError("URL credentials are not allowed")
    _validate_public_host(parts.hostname, resolve=resolve)
    return url


def validate_public_git_url(url: str) -> str:
    # Keep repository ingestion on HTTPS only. Other git transports have a wider
    # protocol surface and are harder to constrain safely in a web request path.
    return validate_public_http_url(url, allow_http=False, resolve=True)

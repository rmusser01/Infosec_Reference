"""Pure request decisions shared by the filtering proxy and offline tests."""
import ipaddress
import socket
import re
from urllib.parse import urlsplit, urlunsplit


def fetch_url(value):
    u = urlsplit(value)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.port not in (None, 80, 443):
        raise ValueError('Unsupported URL, credentials or port')
    return urlunsplit((u.scheme, u.netloc, u.path or '/', u.query, ''))


def public_address(host, port, resolver=None):
    if port not in (80, 443):
        raise ValueError('Unsupported port')
    addresses = resolver(host, port) if resolver else [r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    if not addresses:
        raise ValueError('No DNS answers')
    for value in addresses:
        address = ipaddress.ip_address(value)
        address = getattr(address, 'ipv4_mapped', None) or address
        if address.version == 6 and (address.sixtofour or address.teredo or address in ipaddress.ip_network('64:ff9b::/96')):
            raise ValueError('IPv6 translation/tunnel address')
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError('Non-public destination')
    return addresses[0]


def request_allowed(value, destination, config):
    try:
        value = fetch_url(value)
        if tracking_asset(value):
            return False
        if value in config['documents']:
            return destination not in ('iframe', 'frame', 'video', 'audio')
        if destination == 'image' or value in config['images']:
            return value in config['images']
        if destination in ('iframe', 'frame', 'video', 'audio', 'object', 'embed', 'document'):
            return False
        # Unknown third-party dependencies require review, rather than broadening collection.
        origin = urlsplit(value)[:2]
        return destination in ('script', 'style', 'font', 'empty', '') and any(urlsplit(doc)[:2] == origin for doc in config['documents'])
    except (ValueError, KeyError):
        return False


def response_allowed(value, mime, config):
    mime = mime.split(';')[0].strip().lower()
    if mime in ('text/html', 'application/xhtml+xml'):
        return value in config['documents']
    if mime.startswith('image/'):
        return value in config['images']
    return mime in ('text/css','text/javascript','application/javascript','application/json','application/wasm','application/font-woff','application/vnd.ms-fontobject') or mime.startswith('font/')


def tracking_asset(value):
    return bool(re.search(r'(?:^|/)(?:count|analytics|gtag|ga|beacon|pixel|tracking|advertisement)(?:[./_-]|$)', urlsplit(value).path, re.I))


def redirect_body_allowed(value, mime, length, config):
    return response_allowed(value, mime, config) if mime else length == 0

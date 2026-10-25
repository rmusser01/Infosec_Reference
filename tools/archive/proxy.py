"""Filtering at the proxy applies to redirects and every browser dependency."""
import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urljoin
from mitmproxy import ctx
from policy import fetch_url, public_address, request_allowed, response_allowed, redirect_body_allowed

STATE = Path(os.environ.get('ARCHIVE_STATE', '/state'))


class ArchiveFilter:
    def __init__(self):
        self.bytes = 0
        self.redirects = set()
        self.requests = 0
        self.events = 0

    def config(self):
        config = json.loads((STATE / 'policy.json').read_text())
        config['documents'] = list(set(config['documents']) | self.redirects)
        return config

    def event(self, **event):
        self.events += 1
        if self.events > 2048:
            return
        with (STATE / 'events.jsonl').open('a') as output:
            output.write(json.dumps(event) + '\n')

    def running(self):
        (STATE / 'ready').touch()

    async def server_connect(self, data):
        try:
            host, port = data.server.address
            address = await asyncio.wait_for(asyncio.to_thread(public_address, host, port), 15)
            # Pin the checked address; keep the original SNI for upstream TLS verification.
            data.server.address = (address, port)
        except Exception as error:
            data.server.error = str(error)
            self.event(kind='blocked-network', reason=str(error))

    def requestheaders(self, flow):
        try:
            self.requests += 1
            if self.requests > 512:
                if self.requests == 513:
                    self.event(kind='budget-exceeded', reason='Request count limit')
                flow.kill()
                return
            url = fetch_url(flow.request.pretty_url)
            config = self.config()
            destination = flow.request.headers.get('sec-fetch-dest', '')
            if flow.request.method not in ('GET','HEAD') or flow.request.headers.get('authorization') or flow.request.headers.get('upgrade') or flow.request.headers.get('transfer-encoding') or int(flow.request.headers.get('content-length','0')) > 0:
                raise ValueError('Unsupported method, authentication, upgrade or request body')
            if not request_allowed(url, destination, config):
                raise ValueError('Outside article request scope')
            flow.metadata['archive_url'] = url
        except Exception as error:
            self.event(kind='blocked-request', url=flow.request.pretty_url, reason=str(error))
            flow.kill()

    def responseheaders(self, flow):
        try:
            url = flow.metadata.get('archive_url', fetch_url(flow.request.pretty_url))
            config = self.config()
            mime = flow.response.headers.get('content-type','')
            status = flow.response.status_code
            length = int(flow.response.headers.get('content-length','0'))
            if 300 <= status < 400 and flow.response.headers.get('location'):
                if not redirect_body_allowed(url, mime, length, config):
                    self.event(kind='queued-response', url=url, contentType=mime, status=status)
                    raise ValueError('Non-text or unknown redirect body')
                target = fetch_url(urljoin(url, flow.response.headers['location']))
                if url in config['documents']:
                    if len(self.redirects) >= 5:
                        raise ValueError('Redirect limit')
                    self.redirects.add(target)
                elif url in config['images']:
                    # A changed image URL needs explicit article membership confirmation.
                    raise ValueError('Article image redirect requires review')
                self.event(kind='redirect', url=url, target=target, status=status)
            elif not response_allowed(url, mime, config):
                self.event(kind='queued-response', url=url, contentType=mime, status=status)
                raise ValueError('Non-text or out-of-scope response')
            if length > config['maxResponseBytes']:
                raise ValueError('Response byte limit')
            self.event(kind='response', url=url, status=status, contentType=mime)
            total = 0
            def bounded(chunk):
                nonlocal total
                total += len(chunk)
                self.bytes += len(chunk)
                if total > config['maxResponseBytes'] or self.bytes > config['maxNetworkBytes']:
                    self.event(kind='budget-exceeded', url=url)
                    flow.kill()
                    return b''
                return chunk
            flow.response.stream = bounded
        except Exception as error:
            self.event(kind='blocked-response', url=flow.request.pretty_url, reason=str(error))
            flow.kill()


addons = [ArchiveFilter()]

import asyncio
import base64
from http.client import UNAUTHORIZED
from urllib.parse import urlparse

import aiohttp
import gssapi
import www_authenticate

class NegotiateMixin(object):
    def __init__(self, *,
                 negotiate_client_name=None,
                 negotiate_service_name=None,
                 **kwargs):
        self.negotiate_client_name = negotiate_client_name
        self.negotiate_service_name = negotiate_service_name
        self.negotiate_contexts = {}
        super().__init__(**kwargs)

    def get_negotiate_context(self, host):
        if host not in self.negotiate_contexts:
            service_name = gssapi.Name(self.negotiate_service_name or \
                                       'HTTP@{0}'.format(host),
                                       gssapi.NameType.hostbased_service)
            if self.negotiate_client_name:
                creds = gssapi.Credentials(name=gssapi.Name(self.negotiate_client_name),
                                           usage='initiate')
            else:
                creds = None
            self.negotiate_contexts[host] = gssapi.SecurityContext(name=service_name,
                                                                   creds=creds)
        return self.negotiate_contexts[host]

    def negotiate_step(self, ctx, in_token=None):
        if in_token:
            in_token = base64.b64decode(in_token)
        out_token = ctx.step(in_token)
        if out_token:
            out_token = base64.b64encode(out_token).decode('utf-8')
        return out_token

    @asyncio.coroutine
    def request(self, method, url, headers=None, **kwargs):
        host = urlparse(url).hostname
        headers = headers or {}
        resp = yield from super().request(method, url, headers=headers, **kwargs)
        challenges = {}
        for k, v in resp.headers.items():
            if k.lower() == 'www-authenticate':
                challenges.update(www_authenticate.parse(v))
        if resp.status == UNAUTHORIZED and 'negotiate' in challenges:
            host = urlparse(resp.url).hostname
            self.negotiate_contexts.pop(host, None)
            ctx = self.get_negotiate_context(host)
            out_token = self.negotiate_step(ctx)
            while True:
                resp.close()
                if out_token:
                    headers['Authorization'] = 'Negotiate ' + out_token
                resp = yield from super().request(method, url, headers=headers, **kwargs)
                challenges = www_authenticate.parse(resp.headers.get('WWW-Authenticate'))
                in_token = challenges['negotiate']
                self.negotiate_step(ctx, in_token)
                if ctx.complete:
                    break
        return resp

class NegotiateClientSession(NegotiateMixin, aiohttp.ClientSession):
    pass


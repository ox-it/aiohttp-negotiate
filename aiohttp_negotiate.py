import asyncio
import base64
from http.client import UNAUTHORIZED
from urllib.parse import urlparse

import aiohttp
import gssapi
import www_authenticate

class NegotiateMixin(object):
    def __init__(self, *,
                 negotiate_service='HTTP',
                 negotiate_service_name=None,
                 negotiate_preempt=None,
                 **kwargs):
        self.negotiate_service = negotiate_service
        self.negotiate_service_name = negotiate_service_name
        self.negotiate_contexts = {}
        self.negotiate_preempt = negotiate_preempt
        super().__init__(**kwargs)

    @property
    def negotiate_username(self):
        credential = gssapi.Credential(usage=gssapi.C_INITIATE)
        return str(credential.name)

    def get_negotiate_context(self, host):
        if host not in self.negotiate_contexts:
            service_name = gssapi.Name(self.negotiate_service_name or \
                                       '{0}@{1}'.format(self.negotiate_service, host),
                                       gssapi.C_NT_HOSTBASED_SERVICE)
            self.negotiate_contexts[host] = gssapi.InitContext(service_name)
        return self.negotiate_contexts[host]

    def get_negotiate_auth_header(self, ctx, in_token):
        if in_token:
            in_token = base64.b64decode(in_token).decode('utf-8')
        out_token = ctx.step(in_token)
        out_token = base64.b64encode(out_token).decode('utf-8')
        return 'Negotiate ' + out_token

    @asyncio.coroutine
    def request(self, method, url, headers=None, **kwargs):
        host = urlparse(url).hostname
        headers = headers or {}
        if self.negotiate_preempt or host in self.negotiate_contexts:
            ctx = self.get_negotiate_context(host)
            headers['Authorization'] = self.get_negotiate_auth_header(ctx, None)
        resp = yield from super().request(method, url, headers=headers, **kwargs)
        challenges = www_authenticate.parse(resp.headers.get('WWW-Authenticate'))
        if resp.status == UNAUTHORIZED and 'Negotiate' in challenges:
            host = urlparse(resp.url).hostname
            ctx = self.get_negotiate_context(host)
            while not ctx.established:
                in_token = challenges['Negotiate']
                headers['Authorization'] = self.get_negotiate_auth_header(ctx, in_token)
                resp = yield from super().request(method, url, headers=headers, **kwargs)
        return resp

class NegotiateClientSession(NegotiateMixin, aiohttp.ClientSession):
    pass


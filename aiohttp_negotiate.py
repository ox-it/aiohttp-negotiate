import asyncio
import logging
import socket
import ssl

import base64
from http.client import UNAUTHORIZED

import aiohttp
import gssapi
import www_authenticate

logger = logging.getLogger(__name__)


class NegotiateMixin(object):
    def __init__(self, *,
                 negotiate_client_name=None,
                 negotiate_service_name=None,
                 negotiate_service='HTTP',
                 **kwargs):
        self.negotiate_client_name = negotiate_client_name
        self.negotiate_service_name = negotiate_service_name
        self.negotiate_service = negotiate_service
        super().__init__(**kwargs)

    def get_hostname(self, response):
        assert isinstance(response, aiohttp.ClientResponse)
        assert isinstance(response.connection, aiohttp.connector.Connection)
        sock = response.connection._transport.get_extra_info('socket')
        assert isinstance(sock, (ssl.SSLSocket, socket.socket))
        return socket.gethostbyaddr(sock.getpeername()[0])[0]

    def get_context(self, host):
        service_name = gssapi.Name(self.negotiate_service_name or '{0}@{1}'.format(self.negotiate_service, host),
                                   gssapi.NameType.hostbased_service)
        logger.debug("Service name: {0}".format(service_name))
        if self.negotiate_client_name:
            creds = gssapi.Credentials(name=gssapi.Name(self.negotiate_client_name),
                                       usage='initiate')
        else:
            creds = None
        logger.debug("Credentials: {0}".format(creds))
        return gssapi.SecurityContext(name=service_name,
                                      creds=creds)

    def get_challenges(self, response):
        challenges = {}
        for k, v in response.headers.items():
             if k.lower() == 'www-authenticate':
                 challenges.update(www_authenticate.parse(v))
        logger.debug('Server challenges: {}'.format(challenges))
        return challenges

    def negotiate_step(self, ctx, in_token=None):
        if in_token:
            in_token = base64.b64decode(in_token)
        out_token = ctx.step(in_token)
        if out_token:
            out_token = base64.b64encode(out_token).decode('utf-8')
        return out_token

    @asyncio.coroutine
    def _request(self, method, url, *, headers=None, **kwargs):
        headers = headers or {}
        response = yield from super()._request(method, url, headers=headers, **kwargs)
        challenges = self.get_challenges(response)
        if response.status == UNAUTHORIZED and 'negotiate' in challenges:
            host = self.get_hostname(response)
            ctx = self.get_context(host)
            out_token = self.negotiate_step(ctx)
            while True:
                response.close()
                if out_token:
                    headers['Authorization'] = 'Negotiate ' + out_token
                    response = yield from super()._request(method, url, headers=headers, **kwargs)
                challenges = www_authenticate.parse(response.headers.get('WWW-Authenticate'))
                in_token = challenges['negotiate']
                self.negotiate_step(ctx, in_token)
                if ctx.complete:
                    break
        return response

class NegotiateClientSession(NegotiateMixin, aiohttp.ClientSession):
    pass


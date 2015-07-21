aiohttp-negotiate
=================

A mixin for supporting Negotiate authentication with aiohttp.

Usage
-----

.. code::

   from aiohttp_negotiate import NegotiateClientSession

   session = NegotiateClientSession()
   resp = yield from session.get('https://example.com/')



#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This is a usage example of aiocoap that demonstrates how to implement a
simple server. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import logging

import asyncio

import aiocoap.resource as resource

import aiocoap


class funziona(resource.Resource):
    async def render_get(self, request):
        text="Funziona"
        return aiocoap.Message(payload="\n".join(text).encode('utf8'))

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    AIOCOAP_DTLSSERVER_ENABLED=True
    aiocoap.AIOCOAP_DTLSSERVER_ENABLED=True
    
    # Resource tree creation
    root = resource.Site()
    root.add_resource(['*'], funziona())
    dtls_modules = aiocoap.defaults.dtls_missing_modules()
    print(dtls_modules)
    trans=aiocoap.defaults.get_default_clienttransports()
    server_cr={'coaps://127.0.0.1/': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}}
    
    await aiocoap.Context.create_server_context(root,bind=["127.0.0.1",5683], server_credentials=server_cr)

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
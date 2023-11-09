#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This is a usage example of aiocoap that demonstrates how to implement a
simple server. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap
import aiocoap.credentials as credentials


class TimeResource(resource.Resource):
    """Example resource that can be observed. The `notify` method keeps
    scheduling itself, and calls `update_state` to trigger sending
    notifications."""
    def __init__(self):
        super().__init__()
       

    async def render_get(self, request):
        current_time = datetime.datetime.now().isoformat().encode("utf-8")
        try:
            return aiocoap.Message(payload=current_time)
        except:
            pass
        #await server_pino.shutdown()



# logging setup
logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(['time'], TimeResource())
    #server_cr={'coaps://localhost/*': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}}
    server_cr={'coap://127.0.0.1/time': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}}
    server_pino=await aiocoap.Context.create_server_context(root,bind=["127.0.0.1",5683],transports=['tinydtls_server'])
    #await aiocoap.Context.create_server_context(root,bind=["127.0.0.1",5683])
    server_pino.server_credentials.load_from_dict(server_cr)
    # Run forever
    
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        #print(e)
        pass
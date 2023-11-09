"""This is a usage example of aiocoap that demonstrates how to implement a
simple client. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import logging
import asyncio

from aiocoap import *

logging.basicConfig(level=logging.INFO)

async def main():
    protocol = await Context.create_client_context(transports=["tinydtls"])
    protocol.client_credentials.load_from_dict(
            {'coaps://127.0.0.1:5683/*': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}})
    request = Message(code=GET, uri='coaps://127.0.0.1:5683/')

    try:
        response = await protocol.request(request).response
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r'%(response.code, response.payload))

if __name__ == "__main__":
    asyncio.run(main())
    
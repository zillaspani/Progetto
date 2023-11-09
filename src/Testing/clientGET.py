"""This is a usage example of aiocoap that demonstrates how to implement a
simple client. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import logging
import asyncio


from aiocoap import *

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap").setLevel(logging.DEBUG)
async def main():
    #protocol = await Context.create_client_context()
    protocol = await Context.create_client_context(transports=['tinydtls'])
    client_cr={'coaps://127.0.0.1/time': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}}
    protocol.client_credentials.load_from_dict(client_cr)
    request = Message(code=GET, uri='coaps://127.0.0.1/time',mtype=NON,payload=b"PINO")
    
    try:
        response = await protocol.request(request).response
        #await protocol.shutdown()
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r'%(response.code, response.payload))

if __name__ == "__main__":
    asyncio.run(main())

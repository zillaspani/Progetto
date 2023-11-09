import logging
import asyncio

from aiocoap import *
import aiocoap

async def main():
    protocol = await Context.create_client_context()

    request = Message(code=aiocoap.GET, uri='coap://127.0.0.1:5683/dummy')

    try:
        response = await protocol.request(request).response
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r'%(response.code, response.payload))

if __name__ == "__main__":
    asyncio.run(main())
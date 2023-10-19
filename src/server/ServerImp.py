import asyncio
import logging
import socket
import aiocoap
from AbstractServer import AbstractServer
from abc import ABC

class server(AbstractServer):
    def sendResponse(self,response):
        return response

def __init__(self):
        logging.basicConfig(level=logging.INFO)
        ip_address = socket.gethostbyname(socket.gethostname())
        logging.info(f"Running server aiocoap on %s ",ip_address)


async def main():
    try:
        s=server()
        root = aiocoap.resource.Site()
        root.add_resource(('data',), s.DataResource())
        root.add_resource(('receive',), s.ReceiveState())
        root.add_resource(('dummy',), s.DummyResource())
        logging.info(f"Resource tree OK")
        await aiocoap.Context.create_server_context(root)
        await asyncio.get_running_loop().create_future()
        #asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
        #ip_address = socket.gethostbyname(socket.gethostname())
        #logging.info(f"Avvio server aiocoap su %s ",ip_address)
        #asyncio.get_event_loop().run_forever()     
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Server cannot be instantiated")
        exit()

if __name__ == "__main__":
    asyncio.run(main())
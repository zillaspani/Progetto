import asyncio
import logging
import socket
import aiocoap
from AbstractServer import AbstractServer
from abc import ABC

class server(AbstractServer):
    def sendResponse(self,response):
        return response

    
async def main():
    try:
        s=server()
        root = aiocoap.resource.Site()
        root.add_resource(('data',), s.DataResource())
        root.add_resource(('receive',), s.ReceiveState())
        asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
        ip_address = socket.gethostbyname(socket.gethostname())
        logging.info(f"Avvio server aiocoap su %s ",ip_address)
        asyncio.get_event_loop().run_forever()       
    
    except Exception as ex:
        logging.error(ex)
        logging.error("server non instanziato")
        exit()

if __name__ == "__main__":
    asyncio.run(main())
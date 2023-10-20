import asyncio
import logging
import aiocoap
import globalConstants as g
from AbstractServer import AbstractServer


class server(AbstractServer):
    def sendResponse(self,response):
        return response

async def main():
    try:
        s=server()
        root = aiocoap.resource.Site()
        root.add_resource(('data',), s.DataResource(s))
        root.add_resource(('receive',), s.ReceiveState())
        root.add_resource(('dummy',), s.DummyResource())
        logging.info(f"Resource tree OK")
        await aiocoap.Context.create_server_context(root,bind=[g.IP,g.PORT])
        logging.info(f"Avvio server aiocoap su %s e porta %s",g.IP, g.PORT)
        await asyncio.get_running_loop().create_future()
        
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Server cannot be instantiated")
        exit()

if __name__ == "__main__":
    asyncio.run(main())
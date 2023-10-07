import AbstractServer

class server(AbstractServer):
    def sendResponse(self,response):
        return response

if __name__ == "__main__":
    s=server()
    
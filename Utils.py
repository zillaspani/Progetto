import json
class utils:
    '''Classe per metodi di utilità necessari'''
    def json_encoder(self,data,type):
        '''Encoda un dict per essere inviato, es di type='utf-8' '''
        return json.dumps(data).encode(type)
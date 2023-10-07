
class DataResource(resource.Resource):
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    '''

#class Heartbit(resource.Resource):
    '''
    Riceve delle get da attuatore e sensore per sapere se stann bene
    '''

class ReceiveState(resource.Resource):
    '''
    Riceve una get dall'attuatore e restituisce una:
    risposta con codice 2.05
    Funzione che invia nel body della risposta una informazione.
    Attuatore deve inviare un messaggio confermabile
    '''

'''
TO DO:
Sistema che ricevuto un dato e l'indirizzo IP effettui controlli base sui valori
come formato, segno etc poi valuta la coerenza del dato in relazione agli altri
dati disponibili con media comulativa.
WARNING NEL CASO IN CUI IL VALORE CORRENTE RICEVUTO SIA DISCORDE CON LA MEDIA CUMILATIVA
'''

'''
Classe Campo che legge da file json
'''

'''Metodo per lettura di un file json configurazione'''

'''
TO DO: Capire come gestire le politiche di istradamento e federazione
'''

'''
Console carina e coccolosa per le informazioni
'''


if __name__ == "__main__":
    root = resource.Site()
    root.add_resource(('data',), DataResource())
    root.add_resource(('receive',), ReceiveState())
    asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
    asyncio.get_event_loop().run_forever()
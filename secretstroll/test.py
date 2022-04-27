

import jsonpickle

def myFunction():
    myList = list()
    print(bytes(jsonpickle.dumps(myList), 'utf-8'))

myFunction()    
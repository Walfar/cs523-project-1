"""
Classes that you need to complete.
"""

import json
from typing import Any, Dict, List, Union, Tuple

from credential import *

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        pass


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        sk, pk = generate_key(subscriptions)
        pk = [pk, subscriptions]
        return jsonpickle.encode(sk).encode(),jsonpickle.encode(pk).encode()   

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issue_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.
    
        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes

        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """

        # How to serialize/deserialize ?
        server_sk_unserialized = jsonpickle.decode(server_sk)
        server_pk_unserialized = jsonpickle.decode(server_pk)
        issuance_request_unserialized = jsonpickle.decode(issue_request, keys=True)  

        for sub in subscriptions:
            if sub not in server_pk_unserialized[1]:
                raise RuntimeError("A subscription is not valid")          

        attributes = server_pk_unserialized[1]
        # Use all attributes + username as issuer attributes
        Ys = server_pk_unserialized[0][1:len(attributes)+1]
        issuer_attributes = {}
        for attr in attributes[:len(attributes)-1]:
            if attr not in subscriptions:
                issuer_attributes[Ys[attributes.index(attr)]] = attr    
        print("issuer attributes is")
        print(issuer_attributes)        

        response = sign_issue_request(server_sk_unserialized, server_pk_unserialized, issuance_request_unserialized, issuer_attributes)
        return jsonpickle.encode(response).encode()


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        signature_unserialized = jsonpickle.decode(signature, keys=True)
        server_pk_unserialized = jsonpickle.decode(server_pk)

        for attr in revealed_attributes:
            if attr not in server_pk_unserialized[1]:
                raise RuntimeError("Revealed attributes are not valid")  
        
        bool = verify_disclosure_proof(server_pk_unserialized, signature_unserialized, message)
        print(bool)
        return True   



class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        pass


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        # Verifiy user has valid attributes

        server_pk_unserialized = jsonpickle.decode(server_pk)
        attributes = server_pk_unserialized[1]
        pk = server_pk_unserialized[0]
        Ys = pk[1:len(attributes)+1]
        # Construct dictionary of user attributes where each Yi is mapped to the corresponding subscription 
        user_attributes = {}
        for sub in subscriptions:
            Yi = Ys[attributes.index(sub)]
            user_attributes[Yi] = sub
        user_attributes[Ys[len(attributes)-1]] = username    
        # Use t as the state
        issue_request, state = create_issue_request(server_pk_unserialized, user_attributes)
        return jsonpickle.encode(issue_request, keys=True).encode(), state


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        server_response_unserialized = jsonpickle.decode(server_response)
        server_pk_unserialized = jsonpickle.decode(server_pk)

        credentials = obtain_credential(server_pk_unserialized, server_response_unserialized, private_state)
        return jsonpickle.encode(credentials).encode()


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        credentials_unserialized = jsonpickle.decode(credentials)
        print(credentials_unserialized)

        for type in types:
            if type not in credentials_unserialized[1]:
                print(type)
                raise RuntimeError("Attributes are not in the credential")

        server_pk_unserialized = jsonpickle.decode(server_pk)

        return jsonpickle.encode(create_disclosure_proof(server_pk_unserialized, credentials_unserialized, types, message), keys=True).encode()

"""
Classes that you need to complete.
"""

import json
from typing import Any, Dict, List, Union, Tuple

from attr import attributes
from credential import create_issue_request, generate_key, obtain_credential, sign_issue_request, verify_disclosure_proof, create_disclosure_proof

# Optional import
from serialization import jsonpickle
import numpy as np

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
        return jsonpickle.encode(sk), np.array(pk).tobytes
           


    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
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
        server_sk_unserialized = jsonpickle.decode(server_sk)
        server_pk_unserialized = jsonpickle.decode(server_pk)
        issuance_request_unserialized = jsonpickle.decode(issuance_request)

        attributeMap = List[(1, username)]
        for i in range(len(subscriptions)):
            attributeMap.append((i+2, subscriptions))    
        response = sign_issue_request(server_sk_unserialized, server_pk_unserialized, issuance_request_unserialized, attributeMap)
        return jsonpickle.encode(response)


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
        signature_unserialized = jsonpickle.decode(signature)
        server_pk_unserialized = jsonpickle.decode(server_pk)
        
        # what about the attributes ?
        return verify_disclosure_proof(server_pk_unserialized, (signature_unserialized, revealed_attributes), message)



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
        attributeMap = List[(1, username)]
        for i in range(len(subscriptions)):
            attributeMap.append((i+2, subscriptions))  
        server_pk_unserialized = jsonpickle.decode(server_pk)

        return create_issue_request(server_pk_unserialized, attributeMap)


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

        return obtain_credential(server_pk_unserialized, server_response_unserialized)


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
        server_pk_unserialized = jsonpickle.decode(server_pk)

        return create_disclosure_proof(server_pk_unserialized, credentials_unserialized, types, message)

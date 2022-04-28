"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from http import server
from typing import Any, List, Tuple
import hashlib
from hashlib import sha256

from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
import numpy as np
# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any
PublicKey = Any
Signature = Any
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################

def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    L = len(attributes)
    g = G1.generator()
    g_ = G2.generator()
    ys = []
    pk = []
    sk = []
    x = G1.order().random()
    L = len(attributes)
    for i in range(L):
        ys.append(G1.order().random())  
    """ generate pk """     
    pk.append(g)     
    for y in ys:
        pk.append(g ** y)
    pk.append(g_)    
    pk.append(g_ ** x) 
    for y in ys:
        pk.append(g_ ** y)
    """ generate sk """    
    sk.append(x)     
    sk.append(g ** x)   
    for y in ys:
        sk.append(y)        
    return sk, pk



def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    h = G1.generator() ** G1.order().random()   
    while h == G1.neutral_element():
        h = G1.generator() ** G1.order().random()
    sum = sk[0]
    for i in range(1,len(msgs)):
        sum += sk[i+1]* Bn.from_binary(msgs[i])      
    sig = [h, h ** sum]
    return sig


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:

    msgs_values = list()
    for i in range(len(msgs)):
        msgs_values.append(Bn.from_binary(msgs[i]))

    if signature[0] == G1.unity():
        return False  
    e = signature[1].pair(pk[len(msgs)+1])
    e_ = signature[0].pair(pk[len(msgs)+2] * np.prod(np.power(pk[len(msgs)+3:],msgs)))
    return e == e_


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        server_pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    pk = server_pk[0]
    t = G1.order().random()
    Ys = []
    random = list()
    s = list()
    random.append(G1.order().random())
    C =  pk[0] ** t

    for Yi in user_attributes:
        C *= Yi ** Bn.from_binary(bytes(user_attributes[Yi], 'utf-8')) 
        Ys.append(Yi)
        random.append(G1.order().random())

    R = pk[0]**random[0] * np.prod(np.power(Ys,random[1:]))

    c = hashlib.sha256(jsonpickle.encode(pk).encode())
    c.update(jsonpickle.encode(C).encode())
    c.update(jsonpickle.encode(R).encode())
    c = Bn.from_binary(c.digest())
    
    s.append(random[0].mod_sub(c*t, G1.order()))
    index = 1
    for yi in user_attributes:
        s.append((random[index].mod_sub(c* Bn.from_binary(bytes(user_attributes[yi], 'utf-8')), G1.order())))
        index += 1

    return (C,c,s,user_attributes), (t, user_attributes)


def sign_issue_request(
        sk: SecretKey,
        server_pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request
    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    pk = server_pk[0]
    C = request[0]
    c = request[1]
    s = request[2]
    user_attributes = request[3]
    R_prime = (C**c) * (pk[0]**s[0]) 

    index = 1
    for yi in user_attributes:
        R_prime *= yi**s[index]
        index += 1

    c_prime = hashlib.sha256(jsonpickle.encode(pk).encode())
    c_prime.update(jsonpickle.encode(C).encode())
    c_prime.update(jsonpickle.encode(R_prime).encode())
    c_prime = Bn.from_binary(c_prime.digest())
    try :
        assert c==c_prime
    except AssertionError :
        print("The challenge wasn't verified in sign_issue_request")
    g = pk[0]
    X = sk[1]
    u = G1.order().random()
    res = X*C
    for yi in issuer_attributes:
        res *= yi ** Bn.from_binary(bytes(issuer_attributes[yi], 'utf-8'))   
    return (g**u,res**u),issuer_attributes


def obtain_credential(
        server_pk: PublicKey,
        response: BlindSignature,
        state: Any
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    attributes = server_pk[1]

    t = state[0]
    username = list(state[1].values()).pop()

    msgs = {}
    for i in range(len(attributes)):
        msgs[i] = bytes(attributes[i], 'utf-8')
    msgs[len(attributes)] = bytes(username, 'utf-8')
    signature = (response[0][0], response[0][1]/(response[0][0]**t))
    attributes[len(attributes)-1] = username
    return signature, attributes
    

## SHOWING PROTOCOL ##

def create_disclosure_proof(
        server_pk: PublicKey,
        credential: AnonymousCredential,
        disclosed_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    all_attributes = credential[1]
    L = len(all_attributes)+1
    pk = server_pk[0]
    """ Create a disclosure proof """
    r = G1.order().random()
    t = G1.order().random()
    g_tilda = pk[L+1]
    X_tilda = pk[L+2]
    signature = (credential[0][0]**r, ((credential[0][0]**t)*credential[0][1])**r)
    disclosed_attributes_idx = [all_attributes.index(attr) +1 for attr in disclosed_attributes]
    hidden_attributes_idx = [all_attributes.index(attr) +1 for attr in all_attributes if attr not in disclosed_attributes]

    disclosed_attributes_val = [Bn.from_binary(bytes(attr,'utf-8')) for attr in disclosed_attributes]
    hidden_attributes_val = [Bn.from_binary(bytes(attr,'utf-8')) for attr in all_attributes if attr not in disclosed_attributes]

    disclosed_attributes_dict = dict(zip(disclosed_attributes_idx,disclosed_attributes_val))
    hidden_attributes_dict = dict(zip(hidden_attributes_idx,hidden_attributes_val))

    # Left side of equation 

    C = signature[1].pair(g_tilda) / signature[0].pair(X_tilda)
    for i in disclosed_attributes_dict:
        C *= signature[0].pair(pk[L+1+i])**(-disclosed_attributes_dict[i] % G1.order())
    
    # Compute R and s the reponse with the rai and rt ( random values) 

    rt = G1.order().random()
    random = list()
    s = list() 
    R = signature[0].pair(g_tilda) ** rt
    for i in hidden_attributes_dict :
        rai = G1.order().random()
        random.append(rai)
        R *= signature[0].pair(pk[L+1+i])**hidden_attributes_dict[i] % G1.order()

    # derive c = challenge
    c = hashlib.sha256(jsonpickle.encode(pk).encode())
    c.update(jsonpickle.encode(C).encode())
    c.update(jsonpickle.encode(R).encode())
    c.update(message)
    
    s.append((rt-c * t) % G1.order())
    for i in  range(len(disclosed_attributes_idx)) :
        s.append((random[i] - c *disclosed_attributes_val[i])% G1.order())

    pi = (C,c,s) # proof that the signature is valid
    return signature,disclosed_attributes_dict,pi

def verify_disclosure_proof(
        server_pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    pk = server_pk[0]
    L = len(server_pk[1])
    signature = disclosure_proof[0]
    g_tilda = pk[L+1]
    X_tilda = pk[L+2]
    disclosed_attributes_dict = disclosure_proof[1]
   
    C = signature[1].pair(g_tilda) / signature[0].pair(X_tilda)
 
    for i,ai in disclosed_attributes_dict :
        C *= signature[0].pair(pk[L+1+i])**(-ai % G1.order())


    pi = disclosure_proof[2]
    c = pi[1]
    s = pi[2]

    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    hidden_attributes_idx = [i for i in range(1,L+1) if i not in list(disclosed_attributes_dict.values)]
    if signature[0] == G1.unity() or C != pi[0]:
        return False
    R_prime = C** c * (signature[0].pair(g_tilda)**s[0]) 
    for i,sai in zip(hidden_attributes_idx,s[1:]) :
        R_prime *=signature[0].pair(pk[L+1+i])**(-sai) 

     # derive c prime 
    c_prime = hashlib.sha256(jsonpickle.encode(pk).encode())
    c_prime.update(jsonpickle.encode(C).encode())
    c_prime.update(jsonpickle.encode(R_prime).encode())
    c_prime.update(message)    
    return c == c_prime    

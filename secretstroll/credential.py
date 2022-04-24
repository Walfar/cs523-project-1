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

from msilib.schema import Error
from typing import Any, List, Tuple

from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT
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
    g = G1.generator()
    g_ = G2.generator()
    ys = list()
    pk = list()
    sk = list()
    x = G1.order().random()
    for i in range(len(attributes)):
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
        pk.append(y)
    return sk, pk


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    h = G1.order().random()
    h_ = h ** (sk[0] + np.sum(np.matmul(sk[1:],msgs)))
    return h, h_


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    if signature(0) == G1.unity():
        return False
    e = signature(1).pair(pk[len(msgs)+1])
    e_ = signature(0).pair(pk[len(msgs)+2] * np.prod(np.power(pk[len(msgs)+3:],msgs)))
    return e == e_


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    t = G1.order().random()
    g_t = pk[0] ** t
    C = g_t
    attributes = list()
    for i, at in user_attributes:
        C *= pk[i+1] ** at
        attributes.append(at)
    """proof Fiat-Shamir heuristic"""
    """t + hash(g||h||g^t||m).x mod p Schnorr"""
    s = t + G1.hash_to_point(pk[0],pk,C, attributes)
    return C, (g_t, s)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request
    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    C = request[0]
    g_t = request[1][0]
    s = request[1][1]
    g = pk[0]
    attributes = list()

    X = sk[1]
    u = G1.order().random()
    res = X*C
    for i, at in issuer_attributes:
        res *= pk[i+1] ** at
        attributes.append(at)
    expected_s = G1.hash_to_point(g,pk,C,attributes)
    if g**(s - expected_s) != g_t:
        return Error
    return g**u,res**u,attributes


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()

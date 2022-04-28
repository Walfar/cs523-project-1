from inspect import signature
from re import sub
from urllib import response
import pytest
from stroll import *
from credential import *
import petrelic.multiplicative.pairing
from serialization import jsonpickle

def test_generate_ca() :
    attributes = list('foot','tennis','spa','epfl')
    L = len(attributes) # represents the total length of the possible set of subscritpions
    pk,sk = Server.generate_ca(attributes)
    pk = jsonpickle.decode(pk)
    sk = jsonpickle.decode(sk)
    assert(len(pk) == 3 + 2*L)
    assert(len(sk) == 2 + L)
    for i in len(sk) :
        assert(isinstance(sk[i],petrelic.multiplicative.pairing.G1Element))
    for i in len(pk) : 
        assert(isinstance(pk[i],petrelic.multiplicative.pairing.G1Element))

def test_credentials_difference() :
    # Tests if 2 users with the same attributes will get a different credential
    # Tests if for the same user the credentials are different 

    attributes = list('foot','tennis','spa','epfl')
    user_subscriptions = list('foot','epfl')
    username = "Maxou"
    pk,sk =Server.generate_ca(attributes)

    #User registers for authentification
    issue_request1,private_state1 = Client().prepare_registration(pk,username,user_subscriptions)
    issue_request2,private_state2 = Client().prepare_registration(pk,username,user_subscriptions)

    # Clients authentificates user and provides credential

    response1 = Server().process_registration(sk,pk,issue_request1,username,user_subscriptions)
    response2 = Server().process_registration(sk,pk,issue_request1,username,user_subscriptions)
    response3 = Server().process_registration(sk,pk,issue_request2,username,user_subscriptions)

    #User obtains credentials 
    credential1 = Client().process_registration_response(pk,response1,private_state1)
    credential2 = Client().process_registration_response(pk,response2,private_state1)
    credential3 = Client().process_registration_response(pk,response3,private_state2)

    # Check that the issuance requests is different 
    assert(issue_request1 != issue_request2) 

    # Check the response from the server are different 

    assert(response3 != response1)

    # Check the credential are not the same 
    assert(credential1 != credential3)
    assert(credential1 != credential2)

def test_correct_credential() :
    attributes = list('restaurants','gym','dojo','bar')
    user_subscription = list('restaurants','bar')
    username = 'test'
    disclosed_attributes = user_subscription
    message = bytes("(40.741895,-73.989308)",'uft8')
    pk,sk = Server.generate_ca(attributes)

    issue_request,private_state = Client().prepare_registration(pk,username,user_subscription)
    server_response = Server().process_registration(sk,issue_request,user_subscription)
    credential = Client().process_registration_response(pk,server_response,private_state)

    # Signature for request
    signature = Client().sign_request(pk,credential,message,disclosed_attributes)
    assert(Server().check_request_signature(pk,message,disclosed_attributes,signature))

# Tests that the server refuses a wrong credential
def test_uncorrect_credential() : 
    attributes = list('restaurants','gym','dojo','bar')
    user_subscription = list('restaurants','bar')
    username = 'test'
    disclosed_attributes = user_subscription
    message = bytes("(40.741895,-73.989308)",'uft8')
    pk,sk = Server.generate_ca(attributes)

    issue_request,private_state = Client().prepare_registration(pk,username,user_subscription)
    server_response = Server().process_registration(sk,issue_request,user_subscription)
    credential = Client().process_registration_response(pk,server_response,private_state)
    
    # We obtain the signature returned by obtain_credential() in credential.py
    credential =jsonpickle.decode(credential) 
    signature  = credential[0]

    # We tamper the signature 

    signature /= 2
    signature -= 5
    credential = (signature,credential[1])
    credential = jsonpickle.encode(credential).encode()


    # Signature for request
    signature = Client().sign_request(pk,credential,message,disclosed_attributes)
    assert(not Server().check_request_signature(pk,message,disclosed_attributes,signature))

    
def test_subscribed_all() :
    attributes = list('restaurants','gym','dojo','bar')
    user_subscription = attributes
    username = 'test'
    disclosed_attributes = list()
    message = bytes("(40.741895,-73.989308)",'uft8')
    pk,sk = Server.generate_ca(attributes)

    issue_request,private_state = Client().prepare_registration(pk,username,user_subscription)
    server_response = Server().process_registration(sk,issue_request,user_subscription)
    credential = Client().process_registration_response(pk,server_response,private_state)

    # Signature for request with disclosed attributes being empty
    signature = Client().sign_request(pk,credential,message,disclosed_attributes)
    assert(Server().check_request_signature(pk,message,disclosed_attributes,signature))  


def test_wrong_attributes1() : 
    attributes = list('restaurants','gym','dojo','bar')
    false_attributes = list('wrong','attributes')
    username = 'test'
    pk,sk = Server.generate_ca(attributes)    
    with pytest.raises(RuntimeError):
        # This test asserts that a Runtime error will be raised
        issue_request,private_state = Client().prepare_registration(pk,username,false_attributes)

def test_wrong_attributes2() : 
    attributes = list('restaurants','gym','dojo','bar')
    user_subscriptions = list('restaurants','gym')
    false_attributes = list('wrong','attributes')
    username = 'test'
    pk,sk = Server.generate_ca(attributes)    
    with pytest.raises(RuntimeError):
        # This test asserts that a Runtime error will be raised
        issue_request,private_state = Client().prepare_registration(pk,username,user_subscriptions)
        server_response = Server().process_registration(sk,issue_request,false_attributes)

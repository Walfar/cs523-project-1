
import random
from credential import generate_key, sign, verify
from credential import *

def verify_test() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key(attributes)
    signature = sign(sk,msgs)
    assert verify(pk,signature,msgs)
    

def not_verify_test() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key(attributes)
    signature = sign (sk,msgs)
    false_msg = [b'false',b'message',b'to',b'test']
    assert not verify(pk,signature,false_msg)

def verify_pk_changed() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key(attributes)
    sk1,pk1 = generate_key(attributes)
    signature = sign(sk,msgs)
    assert not verify(pk1,signature,msgs)

def verify_create_issue() :
      attributes = ['email','location','credential','age']
      att_and_username = attributes.copy()
      att_and_username.append('maxton')
      print(attributes)
      print(att_and_username)
      subscription = ['email','location']
      
      
      msg = '(42,32)'.encode('utf-8')
       
      sk,pk = generate_key(att_and_username) # keys of the issuer 
      server_pk = (pk,['email','location','credential','age','username'])
      user_index = [0,1,4]
      issuer_index = [2,3]

      print(user_index)
      print(issuer_index)

      user_attributes_dict = {}
      issuer_attributes_dict = {}
      for i in user_index : 
          print(i)
          user_attributes_dict[pk[i+1]] = att_and_username[i]
      
      for i in issuer_index :
          issuer_attributes_dict[pk[i+1]] = att_and_username[i]
      
      request,state = create_issue_request(server_pk,user_attributes_dict)
      response = sign_issue_request(sk,server_pk,request,issuer_attributes_dict)

      credential = obtain_credential(server_pk,response,state)
      disclosure_proof = create_disclosure_proof(server_pk,credential,subscription,msg)
      assert(verify_disclosure_proof(server_pk,disclosure_proof,msg))

verify_test()
not_verify_test()
verify_pk_changed()
verify_create_issue()
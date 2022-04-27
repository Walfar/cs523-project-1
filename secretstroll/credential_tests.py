
import random
from credential import generate_key, sign, verify
from secretstroll.credential import create_disclosure_proof, create_issue_request, obtain_credential, sign_issue_request

def verify_test() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key
    signature = sign(sk,msgs)
    assert verify(pk,signature,msgs)

def not_verify_test() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key
    signature = sign (sk,)
    false_msg = [b'false',b'message',b'to',b'test']
    assert not verify(pk,signature,false_msg)

def verify_pk_changed() :
    attributes = ['email','location','credential','age']
    msgs = [b'email',b'location',b'credential',b'age']
    sk,pk = generate_key
    sk1,pk1 = generate_key
    signature = sign(sk,msgs)
    assert not verify(pk1,signature,msgs)

def verify_create_issue() :
      attributes = ['email','location','credential','age']  
      msg = list()
      for i in range(len(attributes)) : 
          msg.append(attributes[i].encode())
       
      sk,pk = generate_key # keys of the issuer 
      n = random.sample(1,len(attributes)-1) # number of sample to take
      user_index = random.sample(range(0,len(attributes)),n)
      issuer_index = list(range(len(attributes)))
      for i in user_index :
          issuer_index.remove(i)

      print(user_index)
      print(issuer_index)

      user_attributes = list()
      issuer_attributes = list()
      for i in user_index : 
          user_attributes.append(int.from_bytes(msg[i]))
      
      for i in issuer_index :
          issuer_index.append(int.from_bytes(msg[i]))
      
      request = create_issue_request(pk,user_attributes)
      sign_request = sign_issue_request(pk,request,issuer_attributes)

      assert not sign_request.isInstance(None)
      credential = obtain_credential()
      disclosure_proof = create_disclosure_proof(pk,credential,us)

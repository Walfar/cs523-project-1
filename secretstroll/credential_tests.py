
from credential import generate_key, sign, verify

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












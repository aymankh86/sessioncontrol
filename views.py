from django.shortcuts import render
from .models import SessionControl
import datetime
import time
from django.contrib.auth.models import User


def AESencrypt(password, plaintext, base64=False):
    import hashlib, os
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(BLOCK_SIZE)
     
    paddingLength = 16 - (len(plaintext) % 16)
    paddedPlaintext = plaintext+chr(paddingLength)*paddingLength
    derivedKey = password
    for i in range(0,DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    ciphertext = cipherSpec.encrypt(paddedPlaintext)
    ciphertext = ciphertext + iv + salt
    if base64:
        import base64
        return base64.b64encode(ciphertext)
    else:
        return ciphertext.encode("hex")
 
def AESdecrypt(password, ciphertext, base64=False):
    import hashlib
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    if base64:
        import base64
        decodedCiphertext = base64.b64decode(ciphertext)
    else:
        decodedCiphertext = ciphertext.decode("hex")
    startIv = len(decodedCiphertext)-BLOCK_SIZE-SALT_LENGTH
    startSalt = len(decodedCiphertext)-SALT_LENGTH
    data, iv, salt = decodedCiphertext[:startIv], decodedCiphertext[startIv:startSalt], decodedCiphertext[startSalt:]
    derivedKey = password
    for i in range(0, DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    plaintextWithPadding = cipherSpec.decrypt(data)
    paddingLength = ord(plaintextWithPadding[-1])
    plaintext = plaintextWithPadding[:-paddingLength]
    return plaintext


def check_session(token):
	#user_token = request.DATA['user_token']
    #user_utoken = request.DATA['user_token']


    found = SessionControl.objects.get(token=token)
    if found:
    	token_dec = AESdecrypt('token',token)
    	print token_dec
    	username, password, tm = token_dec.split(',')
    	user = User.objects.get(username=username)
    	
    	if user.check_password(password):
    		dt = datetime.datetime.fromtimestamp(int(tm))

    		if dt < found.expire_time.replace(tzinfo=None):
    			print dt
    			print found.expire_time
    			c = found.expire_time.replace(tzinfo=None) - dt
    			found.expire_time = found.expire_time + datetime.timedelta(seconds=72000)
    			found.save()
    			new_time = int(time.time())
    			new_token_comb = '%s,%s,%s' % (username, password, new_time)
    			found.token = AESencrypt('token',new_token_comb)
    			found.save()
    			return found.token
    		else:
    			return 'expired'
    	else:
    		return 'not found'






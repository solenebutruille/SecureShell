import sys
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def crypt_AES(key, message):
    nonce = get_random_bytes(10)
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    nonce = base64.b64encode(nonce)
    ciphertext = cipher.encrypt(message)
    ciphertext = base64.b64encode(ciphertext)
    mac = cipher.digest()
    mac = base64.b64encode(mac)
    msg = nonce.decode("utf-8") + "||" + ciphertext.decode("utf-8") + "||" + mac.decode("utf-8")
    return msg

def decrypt_AES(key, message):
    split = message.split("||")
    nonce = split[0].encode("utf-8")
    ciphertext = split[1].encode("utf-8")
    mac = split[2].encode("utf-8")
    nonce = base64.b64decode(nonce)
    ciphertext = base64.b64decode(ciphertext)
    mac = base64.b64decode(mac)
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mac)
    #    print ("The message is authentic: hdr=%s, pt=%s" % (plaintext, plaintext))
        return plaintext.decode("utf-8")
    except ValueError:
        print ("Key incorrect or message corrupted")

def create_passphrase(salt, password):
    #extends password to 128 bits
    salt.encode("utf-8")
    salt = base64.b64decode(salt)
    print("salt = ", salt)
    key = password.zfill(16)
    iv = salt.zfill(16)
    print("salt = ", iv)
    print("key = ", key)
    #crypt 0..0 with  AES-128-CBS key = password extended iv = salt
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(b"0..............0")
    return base64.b64encode(ciphertext)

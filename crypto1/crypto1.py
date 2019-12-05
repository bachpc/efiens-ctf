from Crypto.Cipher import AES
import random
from secret import flag
def enc(msg):
    # Encrypt the message using random key and IV with AES-128-OFB
    key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    aes_obj = AES.new(key, AES.MODE_OFB, iv)

    cipher = aes_obj.encrypt(msg)

    # Encrypt the IV with AES-128-ECB
    new_aes_obj = AES.new(key, AES.MODE_ECB)
    encryptedIV = new_aes_obj.encrypt(iv)

    return encryptedIV + cipher


print (enc(flag).encode("hex"))
# ed139bafa3833c178afd29f21dc16f94a869c49b90d06373b99e5b8b6db530b5
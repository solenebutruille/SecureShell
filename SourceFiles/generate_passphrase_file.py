import base64
from Crypto.Random    import get_random_bytes
from AES_encryption   import create_passphrase

#Parameters
client_name = "louis98"
client_password = "darkydu38"

#Generation of random salt
salt = get_random_bytes(8)
salt = base64.b64encode(salt)
salt= salt.decode("utf-8")
#Generation of passphrase
passphrase = create_passphrase(salt, client_password).decode("utf-8")
#Creation of content
content = client_name + "\n" + salt + "||" + passphrase

fichier = open("UserCredentials/" + client_name + ".txt", "w")
fichier.write(content)
fichier.close()

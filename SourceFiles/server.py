import os
import sys
import socket
import shutil
import base64
from Crypto.PublicKey import RSA
from Crypto           import Random
from Crypto.Cipher    import PKCS1_OAEP
from AES_encryption   import crypt_AES
from AES_encryption   import decrypt_AES
from AES_encryption   import create_passphrase

def authenticate_client(username, password):
    path = "UserCredentials/" + username + ".txt"
    # Check if path exists
    if os.path.exists(path) :
        indice = 0
        with open(path) as f:
            for line in f:
                indice +=1
                #On first line check if usernames are matching
                if indice == 1 and (username+"\n") != line:
                    print("Usernames doens't match")
                    return False
                #On second line check if passwords are matching
                if indice == 2 :
                    #gets salt and passphrase in file
                    split = line.split("||")
                    salt = split[0]
                    print("salt from file = ", salt)
                    passphrase = split[1]
                    #create passphrase with received password
                    created_pass = create_passphrase(salt, password)
                    print("created passphrsse = ", created_pass, ".")
                    print("passphrase = ", passphrase.encode("utf-8").decode("unicode_escape"), ".")
                    #check if passphrase are matching
                    if created_pass == passphrase.encode("utf-8"):
                        print("Username passphrase matches")
                        return True
                    else :
                        print("Username passphrase doens't match")
                        return False
    else:
        print("Username doesn't exists")
        return False


def comand_processor(command):
    #execute commands
    res = ""
    if "LS" in command:
        res = os.listdir()
        print("liste of documents", res)
        return '\n'.join(res)
    elif "PWD" in command:
        return os.getcwd()
    elif "CD" in command:
        split = command.split(" ")
        os.chdir(split[1])
        return "Current working directory is now " + split[1]
    elif "CP" in command:
        split = command.split(" ")
        doc = split[2] + "/" + split[1]
        dest = split[3]
        shutil.copy(doc, dest)
        res = doc + " was copy in directory " + dest
    elif "MV" in command:
        split = command.split(" ")
        src = split[2] + '/' + split[1]
        shutil.move(src, split[3])
        res = src + " was move in directory " + split[3]
    else:
        print("Wrong command sent by Network Interface")
    return res

def network_interface(port):
    #Create pair public/private key
    key = RSA.generate(1024)
    private_key = key.export_key('PEM')
    public_key = key.publickey().exportKey('PEM')
    encodedBytes_pr_key = base64.b64encode(private_key)
    encoded_pr_key = str(encodedBytes_pr_key, "utf-8")
    encodedBytes_pu_key = base64.b64encode(public_key)
    encoded_pu_key = str(encodedBytes_pu_key, "utf-8")
    print("Generate keys OK")

    #Store it in files
    try:
        with open("ServerKeys/serverpriv.txt", 'wb') as content_file:
            content_file.write(encodedBytes_pr_key)

        with open("ServerKeys/serverpub.txt", 'wb') as content_file:
            content_file.write(encodedBytes_pu_key)
    except:
        print("Keys couldn't be stored in serverpub.txt and serverpriv.txt")
        return
    print("Store Keys in file OK")

    # Initiate server
    try:
        host = socket.gethostname()
        server_socket = socket.socket()  # get instance
        server_socket.bind((host, port))  # bind host address and port together
        print("Starting Server OK")
    except:
        print("Problem initialing server")
        return

    # configure how many client the server can listen simultaneously
    print("Waiting for connection ...")
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    conn.send(encoded_pu_key.encode())  # send data to the client
    print("Send public key OK")

    #Receives data for authentication
    data = conn.recv(1024).decode()
    data = data.encode("utf-8")
    data = base64.b64decode(data)
    print("Data for authentication received OK")

    #Decrypt data using server's private key
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(data)
    datas = decrypted_text.decode('utf-8')

    try:
        infos = datas.split("||")
        #Gets informations : username, passphrase, sessionKey
        username = infos[0]
        passphrase = infos[1]
        sessionKey = infos[2]
        key = sessionKey.encode("utf-8")
        key = base64.b64decode(key)
        print("Key = ", key)
    except:
        print("Authentication Data didn't have the good format")
        return

    #Authenticate client
    if authenticate_client(username, passphrase) == True:
        conn.send("OK".encode())
    else:
        conn.send("NOK".encode())
        return

    while True:
        # receive command from client
        data = conn.recv(1024).decode()
        print("From connected user: " + str(data))
        #Decrypt received data
        if data == "logout":
            break
        plaintext = decrypt_AES(key, data)
        #Execute command sended
        res = comand_processor(plaintext)
        #crypt answer
        res = crypt_AES(key, res.encode("utf-8"))
        #Send answer to client
        conn.send(res.encode())

    conn.close()  # close the connection


if __name__ == '__main__':
    while(True):
        list = sys.argv
        network_interface(int(list[1]))
        restart = input("Do you want to restart server ? yes/no ")
        if restart == "no":
            break
        print("\nRestarting server")

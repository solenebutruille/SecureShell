import os
import socket
import base64
from Crypto.Random import get_random_bytes
from AES_encryption import crypt_AES
from AES_encryption import decrypt_AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

password = "darkydu38"

def network_interface(client_socket, command_to_send, session_key):
    #Translate the command written by user to command understandable for server
    command = ""
    worked = False
    if "listFiles" in command_to_send:
        command = "LS"
        worked = True
    elif "cwd" in command_to_send:
        command = "PWD"
        worked = True
    elif "chgdir" in command_to_send:
        split = command_to_send.split(" ")
        try:
            command = "CD " + split[1]
            worked = True
        except:
            worked = False
    elif "cp" in command_to_send:
        split = command_to_send.split(" ")
        try:
            command = "CP " + split[1] + " "+ split[2] + " " + split[3]
            worked = True
        except:
            worked = False
    elif "mv" in command_to_send:
        split = command_to_send.split(" ")
        try:
            command = "MV "+ split[1] + " " + split[2] + " " + split[3]
            worked = True
        except:
            worked = False
    if worked == False :
        print("Command is not valid, must be either listfiles, cwd, chgdir <directory>, cp or mv : <document> <actual_directory> <next_directoyr>")
        return

    #crypte message to send to server
    message = crypt_AES(session_key, command.encode("utf-8"))
    client_socket.send(message.encode())  # send message
    #receive answer
    data = client_socket.recv(1024).decode()
    #decrypt answer
    answer = decrypt_AES(session_key, data)
    print("Server's Answer : \n", answer)
    return


def user_input_interface(port, name, ipAdrss = 0, sysName = 0):
    host = ""
    #takes whether ip adress of computer or the one in parameter
    if ipAdrss == 0 and sysName == 0:
        host = socket.gethostname()
    elif ipAdrss != 0:
        host = ipAdrss
    else:
        host = sysName
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    #Receives public key from server
    public_key = client_socket.recv(1024).decode()
    pu_key_64 = public_key.encode("utf-8")
    pu_key = base64.b64decode(pu_key_64)
    if not os.path.exists("Local_directory_sshClient"):
        os.makedirs("Local_directory_sshClient")
    with open("Local_directory_sshClient/server_pub.txt", 'wb') as content_file:
        content_file.write("Public Key in base 64 :\n".encode() + pu_key_64)

    #Generate 256 bit AES session Key
    session_key =  get_random_bytes(16)
    session_key_base64 = base64.b64encode(session_key)
    session_key_string = session_key_base64.decode("utf-8")
    print("Session Key = ", session_key)

    #Create message to send to server to authenticate
    message = name + "||" + password + "||" + session_key_string
    print(message)
    #Crypte message with server's public_key
    rsa_public_key = RSA.importKey(pu_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message.encode("utf-8"))
    encrypted_text = base64.b64encode(encrypted_text)
    message = encrypted_text.decode("utf-8")
    client_socket.send(message.encode())

    #Receive Server's answer
    server_answer = client_socket.recv(1024).decode()
    if server_answer == "NOK":
        print("Authentication failed")
        return
    else:
        print("Authentication success. You can now send command to server")
    message = input(">")  # take input

    while message.lower().strip() != 'logout':
        network_interface(client_socket, message, session_key)
        message = input(">")  # again take input

    client_socket.send("logout".encode())
    client_socket.close()  # close the connection

if __name__ == '__main__':
    while(True):
        worked = False
        #Gets Parameters to connect
        message = input("Main > ")
        split = message.split(" ")
        if len(split) == 2:
            try:
                port = int(split[0])
                myName = split[1]
                worked = True
            except :
                worked = False
            try:
                user_input_interface(port, myName)
            except:
                worked = True
                print("Something went wrong in execution of Client. Error may come from port number")
        elif len(split) == 3 and "0" not in split[0] and "1" not in split[0] and "2" not in split[0] and "3" not in split[0] and "4" not in split[0] and "5" not in split[0] and "6" not in split[0] and "7" not in split[0] and "8" not in split[0] and "9" not in split[0] :
            try:
                sysName = split[0]
                port = int(split[1])
                myName = split[2]
                worked = True
            except :
                worked = False
            try:
                user_input_interface(port, myName, sysName = sysName)
            except:
                worked = True
                print("Something went wrong in execution of Client. Error may come from port number or sysName")
        elif len(split) == 3:
            try:
                ipAdrss = split[0]
                port = int(split[1])
                myName = split[2]
                worked = True
            except:
                worked = False
            try:
                user_input_interface(port, myName, ipAdrss = ipAdrss)
            except:
                worked = True
                print("Something went wrong in execution of Client. Error may come from port number or IP adress")
        if worked == False:
            print("Parameters invalid, must be either <IP> <Port> <YourName> or <SystemName> <Port> <YourName> or <Port> <YourName>.")

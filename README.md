# SecureShell
In this project, I implemented a SSH server and a SSH client.  

To create a new User, you have to open the file generate_passphrase_file.py, change the name that you want, 
password that you want and then run it. File will be created in UserCredentials.

To run the project, you need to launch the server : 
python server.py <Port number>
and then go in the file client.py to put the password of the client and then run 
python client.py
and in the name of client, put the name corresponding to password.

If everything works fine, you are able to run the command listfiles, cwd, chgdir absolutepath, cp filename src dest, mv filename src dest
As the file are actually, in order to make client.py work, we need to put informations : 
5000 louis98

To write my code, I looked at the code in : 
https://www.journaldev.com/15906/python-socket-programming-server-client
https://gist.github.com/jbdatko/7425443
https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python

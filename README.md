# dyspatcher

Dyspatcher is a full, standalone and independent communication system (chat) with end-to-end encryption.

The aim is to provide a complete real-time messaging service that can be established by non-specialised personnel in hostyle environments with makeshifts.

The chat client is web-based and runs on any (modern) desktop/mobile browser.

The server is written in python (3.11) and can run on any device that supports this language - workstation, server or even a smartphone.

Integrated features helps to make the service available even in those cases where the device running the server is not directly reachable from the internet.


## Server

The whole application is managed by the file dyspatcher.py

The server can be easily lauched with:
```
python dyspatcher.py
```

By default the web server is listening on localhost (127.0.0.1), port 80. The WebSocket listens on the same IP Address, port 81.

IP Address and ports can be customized with:
 * **-i**, **--ip-address**: Web Server and Web Socket IP Address (default 127.0.0.1)
 * **-p**, **--port**: Web Server port (default 80)
 * **-w**, **--wsport**: Web Socket port (default 81)

Example:
```
python dyspatcher.py -i 192.168.1.100 -p 8000 -w 8001
```


### HTTPS Web Server

Even if messages are never sent unencrypted over the network because of the end-to-end encryption, it's usually preferable to run the server in HTTPS mode.

Furtehrmore, browsers may not allow to use the *crypto.subtle* Javascript Web API over HTTP outside of localhost - so in many cases the use of HTTPS could be not optional.

HTTPS requires SSL certificates. Self-signed SSL certificates can be created with:
```
openssl req -new -x509 -days 365 -nodes -out webserver.crt -keyout webserver.key
```
As per the previous example, the certificate is stored in *webserver.crt* file, whilst the key is stored in *webserver.key*

Self-signed certificate makes the browser to show an alert about the untrusted certificate, asking the user to manually accept the certificate to continue.

The user is also required to accept the certificate for the WebSocket (port 81 by default). When trying to connect to the WebSocket, if the connection fails because of an untrusted SSL certificate, the chat interface shows a warning asking the user to manually accept the SSL certificate for the WebSocket, providing instruction to complete this step.

To avoid these manual steps, browsers can be configured to always accept untrusted certificates.

Obviously, all the problems can be avoided using regular, valid SSL certificates.

HTTPS can be activated with these options:
 * **--ssl-certificate**: SSL certificate file
 * **--ssl-key**: SSL key file
When SSL is enabled, the default Web Server port is changed to 443.

Example:
```
python dyspatcher.py --ssl-certificate webserver.crt --ssl-key webserver.key
```


### SSH Port Forwarding

Whilst there are no problem in a local network, a workstation or smartphone doesn't likely have a public IP Address that allow to reach them from the internet.

Dyspatcher has build-in features to help bypassing this problem via SSH Port Forwarding (also known as SSH Tunneling).

How to configure (and secure) an SSH server to accept tunneling connection is out-of-scope.

On the Dyspatcher side, the **ssh** client is required to be installed on the device, and keys for SSH Public Key Authentication are required.

SSH Port Forwarding can be configured with these options:
 * **--sshpfw-ip-address**: SSH server IP Address
 * **--sshpfw-port**: SSH Server Port
 * **--sshpfw-user**: User on SSH Server
 * **--sshpfw-keyfile**: Key file for SSH Public Key Authentication

**Example**: Dyspatcher is running on a device on a private network with internet access. The local IP Address is *192.168.1.123*. A remote SSH Server is available at *11.22.33.44*, SSH running on the default port *22*, and an user *dyspatcherpfw* is active on the SSH Server and allowed to activate port forwarding. SSH Public Key Authentication is available for user *dyspatcherpfw*, and its private key is stored in the *dyspatcherpfw.key* file.
```
python dyspatcher.py -i 192.168.1.123 --sshpfw-ip-address 11.22.33.44 --sshpfw-port 22 --sshpfw-user dyspatcherpfw --sshpfw-keyfile dyspatcherpfw.key
```
The command starts the server locally, then establishes a tunnel with the SSH Server forwarding the Web (80) and WebSocket (81) ports.
The chat is then available on the local network at ```http://192.168.1.123```, and from the internet at ```http://11.22.33.44```


### How to run on smartphones

Dyspatcher has been tested on Android smartphones with *Termux* (https://termux.dev/).

*python* and the *cryptography* python module have to be installed on the device. *python* should be installed by default with *Termux*.

The *cryptography* python module could require a tweak to install successfully:
```
export RUSTFLAGS+=" -C llvm-args=-opaque-pointers"
pip install cryptography
```


### Administrator interface

The administrator interface is available via command line prompt.

Commands starts with the character **/**. Available commands are:
 * **/users**: list connected users
 * **/kick [username]**: force disconnection of an user
 * **/help**: show help
 * **/quit**: closes all the active connection and stop the service

Messages can be sent to users entering the **@** character followed by the username, a space and then the message (example ```@yoda Hi Yoda!```). Administrator is always allowed to send messages to everybody at once with **@all**

The administrator username is by default **ADMIN**. Administrator username can be customized with:
 * **-n**, **--admin-nickname**: Admin nickname, minimum 4 characters, maximum 15, only numbers or uppercase characters.


### Other parameters

Other available features are:
 * **--welcome**: set a welcome message sent automatically to an user when he/she connects to the service
 * **--disable-all**: by default, users can send messages to the special **@all** destination, that delivers the message to all the connected users. This option disables the **@all** destinations for users (admin can always send to *@all*)
 * **--only-admin**: by default, users can send messages each other. This option allows users to send messages only to the administrator. When set, the users list only shows the administrator, and all the other users are hidden


## Client

The client is web based and runs on any modern desktop/mobile web browser.


## Encryption

Encryption uses RSA-OAEP, and signature uses RSA-PSS with SHA256.

The server generates the local (administrator) keys when started.

When a chat client is opened (in the web browser), the encryption keys are generated. When connecting to the service, the public key is sent and shared with the other connected users (unless the *--only-admin* switch is set starting the server).

Messages are sent encrypted with the destination public key, and signed with the sender private key. Only messages that are correctly decrypted by the destination and with a valid signature are accepted and shown.


### *crypto.subtle* Javascript Web API restrictions

Browsers may not allow to use the *crypto.subtle* Javascript Web API over HTTP outside of localhost. This Web API is used to handle all the encryption.

If the server runs with HTTP and the browser doesn't allow to access the *crypto.subtle* Web API, an error message is shown when the chat client is opened. In that case the only solution is to run the server in HTTPS mode.


### Problems with HTTPS using self-signed SSL certificate

When HTTPS is activated on the server with self-signed certificates, the browsers will require the user to manually accept the certificate (the standard *"This connection is not secure"* alert).

In those cases the certificate needs to be accepted manually for both the Web Server *and* Web Socket. Web Server certificate can be accepted easily following the instruction when opening the chat client. When connecting to the service, if the connection to the Web Socket fails because of a self-signed certificate, instructions to accept the certificate are shown in the chat.


## TODO

 - improve SSH Port Forwarding configuration
 - SSH Port Forwarding now runs fine only on linux with the *ssh* client installed in standard path
 - improve the chat web interface
 - add chat transcription (admin)

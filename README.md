# dyspatcher

*Dyspatcher* is a full, standalone and independent real-time communication system (chat) with end-to-end encryption.

The aim is to provide a complete and secure real-time messaging service that can be activated by non-specialised personnel in hostile environments with makeshifts.

The chat client is web-based and runs on any (modern) desktop/mobile browser.

The server is written in *Python* (3.11) and requires the *cryptography* module. It can run on any device that supports this language - workstation, server or even a smartphone.

Integrated features help to make the service available even in those cases where the device running the server is not directly reachable from the internet.


## TL;DR

Ok, that sounds nice but before reading this whole loooong page you want to give it a try and see if it's worth wasting some time here.

The easiest way is to try it locally. Just execute:

```
python dyspatcher.py
```

to start the service, then connect to ```http://127.0.0.1``` with any browser. You'll be able to chat with yourself, the web interface is the user whilst the command line interface is the admin.

Nice.

Now you want to try it on the network with different devices, maybe to chat between your laptop and the smartphone. Things are a bit more complex since HTTPS is required: if you want to know why, just keep reading this page.

In this package you can find a dummy SSL self-signed certificate (*webserver.crt* and *webserver.key*) to easily start the service over HTTPS. Use this certificate only for this test, please.

If your local IP Address is *192.168.1.123*, then execute:

```
python dyspatcher.py -i 192.168.1.123 --ssl-certificate webserver.crt --ssl-key webserver.key
```

then connect to ```https://192.168.1.123``` to use the chat web interface. Since it's using a self-signed certificate you have to manually accept it. If you are using Firefox you might be required of an extra step, just read the warning that's shown when connecting to the service.

And now, if you are still interested, the long part.

---

## Summary
  * [Server](#server)
    * [HTTPS Web Server](#https-web-server)
    * [SSH Port Forwarding](#ssh-port-forwarding)
    * [How to run on smartphones](#how-to-run-on-smartphones)
    * [Administrator interface](#administrator-interface)
    * [Administrator encryption keys](#administrator-encryption-keys)
    * [Other parameters](#other-parameters)
  * [Client](#client)
    * [Custom encryption keys](#custom-encryption-keys)
    * [Client web interface for administrator](#client-web-interface-for-administrator)
  * [Encryption](#encryption)
    * [*crypto.subtle* Javascript Web API restrictions](#cryptosubtle-javascript-web-api-restrictions)
    * [Problems with HTTPS using self-signed SSL certificate](#problems-with-https-using-self-signed-ssl-certificate)
    * [Encryption with openssl](#encryption-with-openssl)
  * [What you can learn here even if you don't care at all of a chat service](#what-you-can-learn-here-even-though-you-dont-care-at-all-of-a-chat-service)

---

## Server

The whole application is managed by *dyspatcher.py*

The server handles four processes:
 - **Web Server**: provides the chat web interface to clients
 - **Web Socket**: used for the real-time messages exchange
 - **SSH Port Forward** (optional)
 - **Command Prompt**: administrator interface (manegement and messaging)

The application/server can be easily lauched with:

```
python dyspatcher.py
```

By default the Web Server is listening on localhost (127.0.0.1), port 80. The WebSocket listens on the same IP Address, port 81.

IP Address and ports can be customized with:
 * **-i**, **--ip-address**: Web Server and Web Socket IP Address (default 127.0.0.1)
 * **-p**, **--port**: Web Server port (default 80)
 * **-w**, **--wsport**: Web Socket port (default 81)

Example:

```
python dyspatcher.py -i 192.168.1.100 -p 8000 -w 8001
```


### HTTPS Web Server

Even if messages are never sent unencrypted over the network due to the end-to-end encryption, it's usually preferable to run the server in HTTPS mode.

Furtehrmore, browsers may not allow to use the *crypto.subtle* Javascript Web API (used for client-side data encryption) over HTTP outside of localhost - so in many cases the use of HTTPS could not be optional.

HTTPS requires SSL certificates. Self-signed SSL certificates can be created with:

```
openssl req -new -x509 -days 365 -nodes -out webserver.crt -keyout webserver.key
```

As per the previous example, the certificate is stored in *webserver.crt* file, whilst the key is stored in *webserver.key*

Self-signed certificate makes the browser to show an alert about the untrusted certificate, asking the user to manually accept the certificate to continue.

The user is also required to accept the certificate for the WebSocket (port 81 by default). When trying to connect to the WebSocket, if the connection fails because of an untrusted SSL certificate, the chat interface shows a warning asking the user to manually accept the SSL certificate for the Web Socket, providing instructions to complete this step.

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

Whilst there are no problem in a local network, a workstation or smartphone doesn't likely have a public IP Address that allows to reach them from the Internet.

Dyspatcher has build-in features to help bypassing this problem via SSH Port Forwarding (also known as SSH Tunneling).

How to configure (and secure) an SSH server to accept tunneling connection is out-of-scope here.

On the Dyspatcher side, the **ssh** client is required to be installed on the device, along with keys for SSH Public Key Authentication.

SSH Port Forwarding can be configured with these options:
 * **--sshpfw-ip-address**: SSH server IP Address
 * **--sshpfw-port**: SSH Server Port
 * **--sshpfw-user**: User on SSH Server
 * **--sshpfw-keyfile**: Key file for SSH Public Key Authentication

**Example**: Dyspatcher is running on a device on a private network with internet access. A remote SSH Server is available at *11.22.33.44*, SSH running on the default port *22*, and an user *dyspatcherpfw* is active on the SSH Server and allowed to activate port forwarding. SSH Public Key Authentication is available for user *dyspatcherpfw*, and its private key is stored in the *dyspatcherpfw.key* file.

```
python dyspatcher.py --sshpfw-ip-address 11.22.33.44 --sshpfw-port 22 --sshpfw-user dyspatcherpfw --sshpfw-keyfile dyspatcherpfw.key
```

The command starts the server locally, then establishes a tunnel with the SSH Server forwarding the Web (80, default) and WebSocket (81, default) ports. Custom ports, HTTP or HTTPS, are reflected accordingly. The chat is then available on localhost at ```http://127.0.0.1```, and from the internet at ```http://11.22.33.44```


### How to run on smartphones

Dyspatcher has been tested on Android smartphones with *Termux* (https://termux.dev/).

*python* and the *cryptography* python module have to be installed on the device. *python* should be installed by default with *Termux*.

The *cryptography* python module could require a tweak to install successfully in Termux:

```
export RUSTFLAGS+=" -C llvm-args=-opaque-pointers"
pip install cryptography
```


### Administrator interface

The administrator interface is available via command line prompt. The chat interface for administrator is also available via web, please see [Client web interface for administrator](#client-web-interface-for-administrator)

Commands start with the character **/** (slash). Available commands are:
 * **/users**: list connected users
 * **/kick [username]**: force disconnection of an user
 * **/key [private/public]**: export private/public chat encryption keys
 * **/help**: show help
 * **/quit**: closes all the active connection and stops the service

Messages can be sent to users entering the **@** (at) character followed by the username, a space and then the message (example ```@yoda Hi Yoda!```). Administrator is always allowed to send messages to everybody at once with **@all**

The administrator username is by default **ADMIN**. Administrator username can be customized with:
 * **-n**, **--admin-nickname**: Admin nickname, minimum 4 characters, maximum 15, only numbers or uppercase characters.

Administrator username is always all uppercase, whilst normal users usernames are all lowercase (plus digits).


### Administrator encryption keys

By default, at startup a new RSA key is automatically generated for the administrator.

It is possible to use a custom private key (generated with *openssl* or extracted from a previous session) specifying the file with **--admin-private-key**

Example:

```
# Generate a custom private key
openssl genrsa -out private.pem 4096

# Start the service using the custom private key
python dyspatcher.py --admin-private-key private.pem
```

The public key is automatically calculated from the private key.



### Other parameters

Other available startup options are:
 * **--welcome**: set a welcome message sent automatically to an user when he/she connects to the chat
 * **--disable-all**: by default, users can send messages to the special **@all** destination, that delivers the message to all the connected users. This option disables the **@all** destinations for users (admin can always send to *@all*)
 * **--only-admin**: by default, users can send messages each other, and the users list shows all the connected users. This option allows users to send messages only to the administrator. When set, the users list only shows the administrator, and all the other normal users are hidden

---

## Client

The client is web based and runs on any modern desktop/mobile web browser.


### Custom encryption keys

By default, on loading the Web Client generates new random encryption keys (via the *crypto.subtle* Javascript Web API).

It is possible to use custom encryption keys, generated manually. To set the custom keys, click on the *Use custom keys* link on the login form and enter the private and public keys along with the username you want to use.

Encryption keys can be generated with *openssl*:

```
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

### Client web interface for administrator

Administrator can chat via web interface.

To connect to the web interface as administrator, follow these steps:
 - export the private and public key from the standard command line interface with command **/key**
 - open the web chat interface
 - set any username
 - click on *Use custom keys* and enter the administrator keys previously exported from the server
 - click *Connect*

Now the web client is connected to the chat service as administrator. The username in the interface is changed accordingly to the administrator username set when the service was started.

Every message sent or received from the standard command line prompt interface or the client web interface is reflected on the other part. Sent messages show from which interface they were sent. Direct *Admin-to-Admin* messages are allowed between the two interfaces.

Only one administrator can be connected via the web client at any time.


---

## Encryption

Encryption uses RSA-OAEP, and signature uses RSA-PSS with SHA256. AES-GCM is used for public messages sent to all the connected users (*@all* destination).

The server generates by default the local (administrator) keys when started. Custom keys can be used specifying the Private Key file with **--admin-private-key** (see [Administrator interface](#administrator-interface))

When a chat client is opened (in the web browser), the encryption keys are generated. Users have the option to use their own custom keys. When connecting to the service, the public key is sent and shared with the other connected users (unless the *--only-admin* switch is set when starting the server).

Messages are sent encrypted with the destination public key, and signed with the sender private key. Only messages that are correctly decrypted by the destination and with a valid signature are accepted and shown.

Public messages sent to the *@all* destination are encrypted with the symmetric AES-GCM algorithm, and signed as usual with the sender's private key.

The AES-GCM encryption key is generated by the server at startup and sent to clients when they connects to the service.


### *crypto.subtle* Javascript Web API restrictions

Browsers may not allow to use the *crypto.subtle* Javascript Web API over HTTP outside of localhost. This Web API is used to handle all the client-side encryption.

If the server runs with HTTP and the browser doesn't allow to access the *crypto.subtle* Web API, an error message is shown when the chat client is opened. In that case the only solution is to run the server in HTTPS mode.


### Problems with HTTPS using self-signed SSL certificate

When HTTPS is activated on the server with self-signed certificates, the browsers will require the user to manually accept the certificate (the standard *"This connection is not private"* or *"Potential Security Risk Ahead"* alert).

In those cases the certificate needs to be accepted manually for both the Web Server *and* the Web Socket. Web Server certificate can be easily accepted following the instructions from the browser shown when opening the chat client. When connecting to the service, if the connection to the Web Socket fails because of a self-signed certificate, instructions to accept the certificate are shown in the chat.


### Encryption with openssl

Just for reference, some useful commands to encrypt and decrypt messages with openssl from command line.

```
# Encrypt
echo "Hello world" | openssl pkeyutl -encrypt -pubin -inkey public.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 > message.enc

# Decrypt
openssl pkeyutl -decrypt -inkey private.key -in message.enc -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
```

---

## What you can learn here even though you don't care at all of a chat service

Here you can learn:
 - how to handle multiprocessing in Python
 - how to use Web Socket in Python and Javascript
 - how to implement a Web Server in Python to serve files and contents
 - how to use RSA cryptography in Python (*cryptography* module), JavaScript (*crypto.subtle* Web API) and OpenSSL (command line), and how to decrypt and verify the signature of messages encrypted and signed in different programming languages
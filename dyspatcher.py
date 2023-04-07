###########################################################
#
# Dyspatcher
# https://github.com/wizlab-it/dyspatcher
#
# BSD 3-Clause License
# Copyright (c) 2023, WizLab.it
# See LICENSE file
#
###########################################################
PROGNAME = 'Dyspatcher'
AUTHOR = 'WizLab.it'
VERSION = '0.9'
BUILD = '20230407.135'
###########################################################

import argparse
import asyncio
import websockets
import json
import html
import sys
import os
import re
import time
import socket
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


#
# Configurations
#
WEBSERVER_IP = '127.0.0.1'
WEBSERVER_PORT = 80
WEBSOCKET_PORT = 81
WEBSERVER_SSL_CONFIG = None
ADMIN = { 'nickname':'ADMIN', 'ws':False, 'custom-private-key':False }
SSH_PFW_CONFIG = None
CRYPTO_CONFIG = { }
MISC_CONFIG = { 'welcome-message':None, 'disable-all':False, 'only-admin':False }


#
# Constants and other inits
#

# Text formats
TXT_RED = '\033[31m'
TXT_GREEN = '\033[32m'
TXT_ORANGE = '\033[33m'
TXT_BLUE = '\033[34m'
TXT_PURPLE = '\033[35m'
TXT_CYAN = '\033[36m'
TXT_BOLD = '\033[1m'
TXT_ITALIC = '\033[3m'
TXT_CLEAR = '\033[0m'
TXT_PREVLINE = '\033[F'

# Global variables
CLIENTS = {}
WEBSERVER = None


###########################################################

#
# WebServer Engine Class
#
class ChatWebServer(BaseHTTPRequestHandler):

  # Silent webserver, do not log connections
  def log_message(self, format, *args):
    if(self.path == '/'):
      printPrompt(TXT_CYAN + '[i] [WEB Server] Web interface loaded from ' + self.request.getpeername()[0] + TXT_CLEAR)

  # Process GET requests
  def do_GET(self):
    match self.path:

      # dyspatcher.html file
      case '/':
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        with open('dyspatcher.html', 'rb') as file:
          dyspatcher_html = file.read().replace(b'__WEBSOCKET_PORT_TOKEN__', bytes(str(WEBSOCKET_PORT) + ',' + ('false' if (WEBSERVER_SSL_CONFIG == None) else 'true'), 'utf8'))
          self.wfile.write(dyspatcher_html)

      # dyspatcher.js file
      case '/dyspatcher.js':
        self.send_response(200)
        self.send_header('Content-type', 'application/javascript')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        with open('dyspatcher.js', 'rb') as file:
          self.wfile.write(file.read())

      # unknown file, error 404
      case _:
        self.send_error(404)


###########################################################

#
# Chat Engine
#
async def chatEngine(websocket):
  websocketId = str(websocket.id)
  printPrompt(TXT_CYAN + '[i] [WEB Socket] Connection open from ' + websocket.remote_address[0] + TXT_CLEAR)

  # Add new client to the list of clients and process communication
  try:
    async for payload in websocket:

      # Check if payload is JSON, if not set a fake payload
      try:
        payloadObj = json.loads(payload)
      except:
        payloadObj = {'cmd':''}

      # Process payload
      match payloadObj['cmd']:

        # Command is a normal message, print on the console and dispatch
        case 'message':
          await processMessage(websocketId, payloadObj['user'], payloadObj['data'])

        # Command is a signal, log the message and dispatch
        case 'signal':
          match payloadObj['data']['code']:

            # Signal is an user that joined the chat
            case 'chat-join':
              try:

                # Check if user is valid
                if((not re.compile('^[a-z0-9]{4,15}$').match(payloadObj['user'])) or (not isUserValid(payloadObj['user']))):
                  await sendCommand('signal', '', { 'code':'chat-invaliduser' }, [websocket])
                  await websocket.close()
                  raise Exception("Invalid username")

                # Process key
                keyhash = hashlib.sha256(payloadObj['data']['publickey'].encode('utf-8')).hexdigest()
                keyRSA = serialization.load_pem_public_key(('-----BEGIN PUBLIC KEY-----\n' + payloadObj['data']['publickey'] + '\n-----END PUBLIC KEY-----').encode('utf-8'))

                # If the public key hash is the same of the admin public key hash, then the connected client is the admin via web interface
                if(CRYPTO_CONFIG['publickey-hash'] == keyhash):

                  # If there is another admin via web then reject the connection
                  if(ADMIN['ws'] != False):
                    await sendCommand('signal', '', { 'code':'notice', 'notice':'Admin is already connected via web interface' }, [websocket])
                    await websocket.close()
                    raise Exception("Admin is already connected via web")

                  # Set the isAdmin flag and change the username to the admin username
                  payloadObj['user'] = ADMIN['nickname']
                  ADMIN['ws'] = websocketId

                # Create entry in clients list
                CLIENTS[websocketId] = { 'ws':websocket, 'ip':websocket.remote_address, 'user':payloadObj['user'], 'isAdmin':(True if (ADMIN['ws'] == websocketId) else False), 'publickey': { 'hash':keyhash, 'text':payloadObj['data']['publickey'], 'rsa':keyRSA } }

                # Send config
                await sendCommand('config', '', { 'disable-all':MISC_CONFIG['disable-all'], 'user':CLIENTS[websocketId]['user'], 'is-admin':CLIENTS[websocketId]['isAdmin'], 'keyid':keyhash, 'aeskey':CRYPTO_CONFIG['aeskey']['b64'] }, [websocket])

                # Send users list
                userslist = [ {'name':ADMIN['nickname'], 'publickey':{ 'hash':CRYPTO_CONFIG['publickey-hash'], 'text':CRYPTO_CONFIG['publickey-text'] } } ]
                # Add normal users to the list only if only-admin flag is not set OR user is the admin via web
                if((MISC_CONFIG['only-admin'] == False) or CLIENTS[websocketId]['isAdmin']):
                  for c in CLIENTS:
                    # Exclude admin via web from users list
                    if(CRYPTO_CONFIG['publickey-hash'] == CLIENTS[c]['publickey']['hash']):
                      continue
                    userslist.append({'name':CLIENTS[c]['user'], 'publickey':{ 'hash':CLIENTS[c]['publickey']['hash'], 'text':CLIENTS[c]['publickey']['text'] } })
                await sendCommand('signal', '', { 'code':'chat-userslist', 'userslist':json.dumps(userslist) }, [websocket])

                # Send welcome message if set
                if(MISC_CONFIG['welcome-message'] != None):
                  await sendRSAMessage(ADMIN['nickname'], CLIENTS[websocketId], html.escape(MISC_CONFIG['welcome-message']))

                # If connected client is not admin via web, che if to send the join notification
                if(not CLIENTS[websocketId]['isAdmin']):
                  joinNotificationPayload = { 'code':'chat-join', 'publickey':{ 'hash':keyhash, 'text':payloadObj['data']['publickey'] } }

                  # If only-admin flag is set then send only to the admin via web (if any), otherwise send to everybody
                  if(MISC_CONFIG['only-admin']):
                    if(ADMIN['ws'] != False):
                      await sendCommand('signal', payloadObj['user'], joinNotificationPayload, [CLIENTS[ADMIN['ws']]['ws']])
                  else:
                    await sendCommand('signal', payloadObj['user'], joinNotificationPayload)

                # Show notification on admin interface
                printPrompt(TXT_ORANGE + TXT_ITALIC + CLIENTS[websocketId]['user'] + ' joined chat' + TXT_CLEAR)

              except:
                pass


  # Required to handle websocket error on disconnecting client
  except(websockets.exceptions.ConnectionClosedError):
    pass

  # When connection is closed, then remove client from list
  finally:
    if websocketId in CLIENTS:
      user_tmp = CLIENTS[websocketId]['user']
      del CLIENTS[websocketId]
      if(websocketId == ADMIN['ws']):
        ADMIN['ws'] = False
      else:
        await sendCommand('signal', user_tmp, { 'code':'chat-left' })
      printPrompt(TXT_ORANGE + TXT_ITALIC + user_tmp + ' abandoned chat' + TXT_CLEAR)
    printPrompt(TXT_CYAN + '[i] [WEB Socket] Connection closed by ' + websocket.remote_address[0] + TXT_CLEAR)


#
# Process message
#
async def processMessage(websocketId, user, data):
  ciphertextB64 = data['ciphertext'].strip()
  if(ciphertextB64 == ''):
    return

  # Check encryption algorithm
  match data['algo']:

    # AES encryption (@all message)
    case 'aes':
      plaintext = aesDecrypt(base64.b64decode(data['iv']), base64.b64decode(ciphertextB64))
      if(plaintext != False):
        plaintextObj = json.loads(plaintext.decode('latin1'))

        # Block @all message is disable-all flag is set
        if((plaintextObj['to'] == 'all') and (not CLIENTS[websocketId]['isAdmin']) and MISC_CONFIG['disable-all']):
          return

        #Check message signature
        signature = base64.b64decode(data['signature'])
        try:
          # Verify signature
          CLIENTS[websocketId]['publickey']['rsa'].verify(signature, plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256), hashes.SHA256())

          # If here, signature is ok

          # If message is from admin web, then change the sender before to show in local chat
          if(CLIENTS[websocketId]['isAdmin']):
            plaintextObj['from'] = TXT_RED + plaintextObj['from'] + ' (via web)'

          # Print message locally and forward to others
          printPrompt('From ' + TXT_GREEN + TXT_BOLD + plaintextObj['from'] + TXT_CLEAR + ' to ' + TXT_GREEN + TXT_BOLD + plaintextObj['to'] + TXT_CLEAR + ': ' + plaintextObj['message'])
          await sendCommand('message', '', data)

        except:
          pass

    # RSA encryption (1-to-1 message)
    case 'rsa':

      # Try to decrypt: if successful, them message is for admin so do not forward to anyone
      try:
        client = getClientByUser(user)
        ciphertext = base64.b64decode(ciphertextB64)
        plaintext = CRYPTO_CONFIG['privatekey'].decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        plaintext = plaintext.decode('latin1')
        signature = base64.b64decode(data['signature'])

        # If here, it's already known that message is for admin: check signature and print if ok
        try:
          # Verify signature
          client['publickey']['rsa'].verify(signature, plaintext.encode('latin1'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256), hashes.SHA256())
          plaintextObj = json.loads(plaintext)

          # If here, signature is ok

          # Check if the received message is just the server copy of a message sent from the admin via web interface
          if(CLIENTS[websocketId]['isAdmin']):
            printPrompt('From ' + TXT_RED + TXT_BOLD + plaintextObj['from'] + ' (via web)' + TXT_CLEAR + ' to ' + TXT_GREEN + TXT_BOLD + plaintextObj['to'] + TXT_CLEAR + ': ' + plaintextObj['message'])
            return
          else:
            printPrompt('From ' + TXT_GREEN + TXT_BOLD + plaintextObj['from'] + TXT_CLEAR + ' to ' + TXT_RED + TXT_BOLD + plaintextObj['to'] + TXT_CLEAR + ': ' + plaintextObj['message'])
            if(ADMIN['ws']):
              await sendCommand('message', '', data, [CLIENTS[ADMIN['ws']]['ws']])
              return

        # Signature verification failed
        except:
          pass

        return

      # Unable to decrypt message (invalid key)
      except:
        pass

      # If here, message is not for admin (unable to decrypt), so forward to clients
      await sendCommand('message', '', data)


#
# Dispatch the command to clients
#
async def sendCommand(cmd, user, data, wss=False):
  # If no wss specified, then build wss list with all clients
  if(wss == False):
    wss = []
    for c in CLIENTS:
      wss.append(CLIENTS[c]['ws'])

  # Send payload to wss list
  payload = json.dumps({ 'cmd':cmd, 'user':user, 'data':data })
  for ws in wss:
    await ws.send(payload)


#
# Send message
#
async def sendAESMessage(sender, destination, message):
  payload = json.dumps({'from':sender, 'to':destination, 'message':message}).encode('utf-8')
  (iv, ciphertext) = aesEncrypt(payload)
  signature = base64.b64encode(CRYPTO_CONFIG['privatekey'].sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256), hashes.SHA256())).decode('utf-8')
  await sendCommand('message', '', { 'iv':base64.b64encode(iv).decode('utf-8'), 'ciphertext':base64.b64encode(ciphertext).decode('utf-8'), 'signature':signature, 'algo':'aes' })

async def sendRSAMessage(sender, destination, message, flags={}):
  # Build payload
  payload = { 'from':sender, 'to':destination['user'], 'message':message }
  if(('isWebAdminMsgCopy' in flags) and flags['isWebAdminMsgCopy']): payload['isWebAdminMsgCopy'] = True

  # Pack payload, encrypt, sign and send
  payload = json.dumps(payload).encode('utf-8')
  signature = base64.b64encode(CRYPTO_CONFIG['privatekey'].sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256), hashes.SHA256())).decode('utf-8')
  ciphertext = base64.b64encode(destination['publickey']['rsa'].encrypt(payload, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8')
  await sendCommand('message', '', { 'ciphertext':ciphertext, 'signature':signature, 'algo':'rsa' }, [destination['ws']])


#
# Get websocket from CLIENTS list by user
#
def getClientByUser(user):
  for c in CLIENTS:
    if CLIENTS[c]['user'] == user:
      return CLIENTS[c]
  return False


#
# Close all chat clients
#
async def chatClose():
  # Get list of websockets
  ws_tmp = set()
  for c in CLIENTS:
    ws_tmp.add(CLIENTS[c]['ws'])

  # Clear clients
  CLIENTS.clear()

  # Close all websockets
  for ws in ws_tmp:
    await ws.close()


###########################################################

#
# Initialization methods
#

# Init Crypto
def initCrypto():

  # Check if a custom private key for admin is provided
  if(ADMIN['custom-private-key']):
    try:
      if(not re.compile('^[a-zA-Z0-9\-\.]{1,30}$').match(ADMIN['custom-private-key'])):
        raise Exception('invalid file name')
      if(not os.path.isfile(ADMIN['custom-private-key'])):
        raise Exception('file does not exists')

      # Load private key
      with open(ADMIN['custom-private-key'], 'rb') as privateKeyFile:
        CRYPTO_CONFIG['privatekey-pem'] = privateKeyFile.read()
        CRYPTO_CONFIG['privatekey'] = serialization.load_pem_private_key(CRYPTO_CONFIG['privatekey-pem'], password=None)
        if(not isinstance(CRYPTO_CONFIG['privatekey'], rsa.RSAPrivateKey)):
          raise Exception('file does not contain an RSA private key')

    except Exception as e:
      printPrompt(TXT_RED + TXT_BOLD + '[-] Crypto error, invalid private key file: ' + str(e) + TXT_CLEAR)
      return False

  # No custom private key, generate a new random admin private key
  else:
    CRYPTO_CONFIG['privatekey'] = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    CRYPTO_CONFIG['privatekey-pem'] = CRYPTO_CONFIG['privatekey'].private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

  # Generate admin public key from private key
  CRYPTO_CONFIG['publickey'] = CRYPTO_CONFIG['privatekey'].public_key()
  CRYPTO_CONFIG['publickey-pem'] = CRYPTO_CONFIG['publickey'].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
  CRYPTO_CONFIG['publickey-text'] = packPublicKey(CRYPTO_CONFIG['publickey-pem'])
  CRYPTO_CONFIG['publickey-hash'] = hashlib.sha256(CRYPTO_CONFIG['publickey-text'].encode('utf-8')).hexdigest()

  # Generate AES 256bit key for @all destination
  CRYPTO_CONFIG['aeskey'] = { 'bin':os.urandom(32) }
  CRYPTO_CONFIG['aeskey']['b64'] = base64.b64encode(CRYPTO_CONFIG['aeskey']['bin']).decode('utf-8')

  # Crypto init done
  printPrompt('[+] ... Crypto started (random keys generated)')
  return True


# Init Chat Engine
async def initChatEngine():
  printPrompt('[+] ... Chat Engine started (ws' + ('' if (WEBSERVER_SSL_CONFIG == None) else 's') + '://%s:%s)' % (WEBSERVER_IP, WEBSOCKET_PORT))
  async with websockets.serve(chatEngine, WEBSERVER_IP, WEBSOCKET_PORT, ssl=(WEBSERVER_SSL_CONFIG['context'] if (WEBSERVER_SSL_CONFIG != None) else None)):
    await asyncio.Future()


# Init Prompt
def initPrompt():
  printPrompt('[+] ... Command Prompt started')
  while True:
    promptProcessor()


# Init Web Server
def initWebServer():
  try:
    WEBSERVER = HTTPServer((WEBSERVER_IP, WEBSERVER_PORT), ChatWebServer)
  except:
    printPrompt(TXT_RED + TXT_BOLD + '[-] Web Server cannot start (address already in use?)' + TXT_CLEAR)
    return False

  # Check if SSL is enabled
  if(WEBSERVER_SSL_CONFIG != None):
    try:
      WEBSERVER.socket = WEBSERVER_SSL_CONFIG['context'].wrap_socket(WEBSERVER.socket, server_side=True)
    except:
      printPrompt(TXT_RED + TXT_BOLD + '[-] Web Server cannot start (invalid SSL certificate)' + TXT_CLEAR)
      return False

  webserverUrl = TXT_BLUE + TXT_BOLD + 'http' + ('' if (WEBSERVER_SSL_CONFIG == None) else 's') + '://' + WEBSERVER_IP + ':' + str(WEBSERVER_PORT) + TXT_CLEAR
  if(SSH_PFW_CONFIG != None): webserverUrl = webserverUrl + ' and ' + TXT_BLUE + TXT_BOLD + 'http' + ('' if (WEBSERVER_SSL_CONFIG == None) else 's') + '://' + SSH_PFW_CONFIG['ip'] + ':' + str(WEBSERVER_PORT) + TXT_CLEAR
  printPrompt('[+] ... Web Server started (' + webserverUrl + ')')
  try:
    WEBSERVER.serve_forever()
  except:
    pass
  WEBSERVER.server_close()


# Init SSH Port Forwarding
def initSSHPFW():
  if(SSH_PFW_CONFIG != None):
    webserverPFW = SSH_PFW_CONFIG['ip'] + ':' + str(WEBSERVER_PORT) + ':127.0.0.1:' + str(WEBSERVER_PORT)
    websocketPFW = SSH_PFW_CONFIG['ip'] + ':' + str(WEBSOCKET_PORT) + ':127.0.0.1:' + str(WEBSOCKET_PORT)
    userhostPFW = SSH_PFW_CONFIG['user'] + '@' + SSH_PFW_CONFIG['ip']
    SSH_PFW_CONFIG['process'] = subprocess.Popen(['ssh', '-p', SSH_PFW_CONFIG['port'], '-N', '-R', webserverPFW, '-R', websocketPFW, '-i', SSH_PFW_CONFIG['key'], userhostPFW])
    printPrompt('[+] ... SSH Port Forward started')


###########################################################

#
# Process Command Prompt
#

def promptProcessor():
  promptInput = input()
  promptInput = promptInput.strip()
  if(promptInput == ''):
    printPrompt(TXT_PREVLINE)
    return

  # Separate first word from rest of the input, then check the first character of the first word
  promptInput = promptInput.split(' ', 1)
  commandOrDestination = promptInput[0][1:].strip()
  match promptInput[0][0]:

    # If input starts with /, then it's a command
    case '/':
      match commandOrDestination:

        # Command: users - list all connected users
        case 'users' | 'u':
          printPrompt('[i] Connected users:')
          printPrompt('[i]   * ' + TXT_RED + TXT_BOLD + ADMIN['nickname'] + TXT_CLEAR + ' (🔒' + TXT_CYAN + CRYPTO_CONFIG['publickey-hash'][:10] + TXT_CLEAR + CRYPTO_CONFIG['publickey-hash'][10:] + ')')
          cnt = 1
          for c in CLIENTS:
            printPrompt('[i]   * ' + CLIENTS[c]['user'] + ' (' + CLIENTS[c]['ip'][0] + ', 🔒' + TXT_CYAN + CLIENTS[c]['publickey']['hash'][:10] + TXT_CLEAR + CLIENTS[c]['publickey']['hash'][10:] + ')')
            cnt = cnt + 1
          printPrompt('[i] ' + str(cnt) + ' user' + ('s' if (cnt != 1) else '') + ' connected')

        # Command: kick - disconnect an user
        case 'kick':
          wsUser = False
          if(len(promptInput) == 2):
            wsUser = getClientByUser(promptInput[1].strip())
          if(wsUser == False):
            printPrompt('[i] Usage: ' + TXT_BOLD + '/kick [username]' + TXT_CLEAR)
            return
          try:
            asyncio.run(wsUser['ws'].close())
          except:
            pass

        # Command: key - show private/public keys
        case 'key' | 'k':
          try:
            match promptInput[1]:
              case 'public' | 'pub':
                printPrompt('\n' + CRYPTO_CONFIG["publickey-pem"].decode('utf-8'))
              case 'private' | 'pri':
                printPrompt('\n' + CRYPTO_CONFIG["privatekey-pem"].decode('utf-8'))
              case _:
                raise Exception('Err')
          except:
            printPrompt('[i] Usage: ' + TXT_BOLD + '/key [public/private]' + TXT_CLEAR)
            return

        # Command: help - show help
        case 'help' | 'h':
          printPrompt('[i] Commands: /' + TXT_BOLD + 'u' + TXT_CLEAR + 'sers, /kick [username], /' + TXT_BOLD + 'k' + TXT_CLEAR + 'ey [' + TXT_BOLD + 'pub' + TXT_CLEAR + 'lic|' + TXT_BOLD + 'pri' + TXT_CLEAR + 'vate], /' + TXT_BOLD + 'h' + TXT_CLEAR + 'elp, /' + TXT_BOLD + 'q' + TXT_CLEAR + 'uit')
          printPrompt('[i] Messages: @{username} {message}')

        # Command: quit - stop the service
        case 'quit' | 'q':
          stopServices()

        # Unknown command
        case _:
          printPrompt('[-] Unknown command. Send ' + TXT_BOLD + '/help' + TXT_CLEAR + ' for help')

    # If input starts with @, then it's a message
    case '@':

      # Check destination and message
      try:
        if(len(commandOrDestination) < 3):
          raise Exception("Destination too short")

        if(len(promptInput) != 2):
          raise Exception("Invalid message")

        message = promptInput[1].strip()
        if(len(message) < 1):
          raise Exception("Invalid message")

        # If destination is not @all, then check if destination exists
        if(commandOrDestination != "all"):
          destination = getClientByUser(commandOrDestination)
          if(destination == False):
            raise Exception("Unknown destination")

      except Exception as e:
        printPrompt('[-] ' + str(e))
        return

      # If there is a admin via web, then send its copy
      if(ADMIN['ws'] != False):
        webCopyPayload = { 'message':message, 'to':commandOrDestination }
        asyncio.run(sendRSAMessage(ADMIN['nickname'], CLIENTS[ADMIN['ws']], json.dumps(webCopyPayload), {'isWebAdminMsgCopy':True}))

      # Print message on console
      printPrompt(TXT_PREVLINE + 'From ' + TXT_RED + TXT_BOLD + ADMIN['nickname'] + TXT_CLEAR + ' to ' + TXT_GREEN + TXT_BOLD + commandOrDestination + TXT_CLEAR + ': ' + message)

      # If message is for @all, then AES encrypt and send, otherwise send normal message
      if(commandOrDestination == "all"):
        asyncio.run(sendAESMessage(ADMIN['nickname'], commandOrDestination, message))
      else:
        asyncio.run(sendRSAMessage(ADMIN['nickname'], destination, message))

    # Invalid input
    case _:
      printPrompt('[-] Invalid input. Send ' + TXT_BOLD + '/help' + TXT_CLEAR + ' for help')


# Output a string on the command prompt
def printPrompt(str):
  print('\r' + str + '\n>>> ', end='', flush=True)


###########################################################

#
# Support methods
#

# Check if username is already used
def isUserValid(user):
  for c in CLIENTS:
    if(CLIENTS[c]['user'] == user):
      return False
  return True


# Validate SSL parameters
def validateWebServerSSL(args):
  SSL_PARAM_CNT = 0

  # Certificate file
  if(args.ssl_certificate != None):
    if(re.compile('^[a-zA-Z0-9\-\.]{1,30}$').match(args.ssl_certificate) and os.path.isfile(args.ssl_certificate)):
      SSL_PARAM_CNT = SSL_PARAM_CNT + 1
    else:
      print('[-] Invalid SSL Certificate file')
      sys.exit(1);

  # Key file
  if(args.ssl_key != None):
    if(re.compile('^[a-zA-Z0-9\-\.]{1,30}$').match(args.ssl_key) and os.path.isfile(args.ssl_key)):
      SSL_PARAM_CNT = SSL_PARAM_CNT + 1
    else:
      print('[-] Invalid SSL Key file')
      sys.exit(1);

  # CA Bundle file
  if(args.ssl_cabundle != None):
    if(not re.compile('^[a-zA-Z0-9\-\.]{1,30}$').match(args.ssl_cabundle) or (not os.path.isfile(args.ssl_cabundle))):
      args.ssl_cabundle = None

  # Check if all params are set
  if(SSL_PARAM_CNT == 0):
    return None
  elif(SSL_PARAM_CNT == 2):
    return True
  else:
    return False


# Validate SSH Port Forward parameters
def validateSSHPFW(args):
  SSHPFW_PARAM_CNT = 0

  # IP Address
  if(args.sshpfw_ip_address != None):
    try:
      socket.inet_pton(socket.AF_INET, args.sshpfw_ip_address)
      SSHPFW_PARAM_CNT = SSHPFW_PARAM_CNT + 1
    except:
      print('[-] Invalid SSH Port Forward IP Address')
      sys.exit(1)

  # Port
  if(args.sshpfw_port != None):
    if((args.sshpfw_port >= 1) and (args.sshpfw_port <= 65535)):
      SSHPFW_PARAM_CNT = SSHPFW_PARAM_CNT + 1
    else:
      print('[-] Invalid SSH Port Forward Port')
      sys.exit(1);

  # User
  if(args.sshpfw_user != None):
    if(re.compile('^[a-zA-Z0-9]{1,20}$').match(args.sshpfw_user)):
      SSHPFW_PARAM_CNT = SSHPFW_PARAM_CNT + 1
    else:
      print('[-] Invalid SSH Port Forward User')
      sys.exit(1);

  # Key File
  if(args.sshpfw_keyfile != None):
    if(re.compile('^[a-zA-Z0-9\-\.]{1,30}$').match(args.sshpfw_keyfile) and os.path.isfile(args.sshpfw_keyfile)):
      SSHPFW_PARAM_CNT = SSHPFW_PARAM_CNT + 1
    else:
      print('[-] Invalid SSH Port Forward Key File')
      sys.exit(1);

  # Check if all params are set
  if(SSHPFW_PARAM_CNT == 0):
    return None
  elif(SSHPFW_PARAM_CNT == 4):
    return True
  else:
    return False


# Remove header and footer from PEM key, and store in a single line
def packPublicKey(key):
  return "".join(key.decode('utf-8').strip().split('\n')[1:-1])


# AES Encrypt
def aesEncrypt(plaintext):
  try:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(CRYPTO_CONFIG['aeskey']['bin']), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag
    return (iv, ciphertext)
  except:
    return False


# AES Decrypt
def aesDecrypt(iv, ciphertext):
  try:
    tag = ciphertext[-16:]
    ciphertext = ciphertext[0:-16]
    decryptor = Cipher(algorithms.AES(CRYPTO_CONFIG['aeskey']['bin']), modes.GCM(iv, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
  except:
    return False


###########################################################

#
# Start and stop services
#

# Start services
async def startServices(args):
  print('[+] Starting services...')

  # Crypto
  if(not initCrypto()):
    printPrompt(TXT_RED + TXT_BOLD + '[-] Error starting crypto' + TXT_CLEAR)
    stopServices()
    sys.exit(0)

  # Web Server
  webserver_t = threading.Thread(target=initWebServer)
  webserver_t.daemon = True
  webserver_t.start()
  time.sleep(0.3)
  if(not webserver_t.is_alive()):
    stopServices()
    sys.exit(0)

  # SSH Port Forward
  if(SSH_PFW_CONFIG != None):
    initSSHPFW()

  # Check if websocket port is available
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((WEBSERVER_IP, WEBSOCKET_PORT))
  except:
    printPrompt(TXT_RED + TXT_BOLD + '[-] Chat Engine cannot start (address already in use?)' + TXT_CLEAR)
    stopServices()
    sys.exit(0)
  s.close()

  # Prompt and chat engine
  try:
    tasks = [asyncio.to_thread(initPrompt), initChatEngine()]
    await asyncio.gather(*tasks)
  except:
    pass


# Stop services
def stopServices():
  # Good bye message
  print('\r[+] Good bye baby')

  # Terminate SSH Port Forwarding if active
  if(SSH_PFW_CONFIG != None):
    try:
      SSH_PFW_CONFIG['process'].terminate()
    except:
      pass

  # Close all chats
  if(len(CLIENTS) > 0):
    asyncio.run(chatClose())

  # Exit
  sys.exit(0)


###########################################################

#
# Main
#

if __name__ == '__main__':
  epilog = '''
  \r\nexamples:\n
  ''' + TXT_BOLD + '''Enable SSL (webserver default port is 443, read note in documentation):''' + TXT_CLEAR + '''
  python ''' + os.path.basename(sys.argv[0]) + ''' --ssl-certificate [ssl-certificate] --ssl-key [ssl-key] --ssl-cabundle [ssl-cabundle]\n
  ''' + TXT_BOLD + '''Enable SSH Port Forward (requires public key authentication on remote host, read note in documentation):''' + TXT_CLEAR + '''
  python ''' + os.path.basename(sys.argv[0]) + ''' --sshpfw-ip-address [remote-host-ip] --sshpfw-port [remote-host-ssh-port] --sshpfw-user [remote-host-ssh-user] --sshpfw-keyfile [remote-host-ssh-user-key]
  '''
  parser = argparse.ArgumentParser(epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument('-i','--ip-address', action='store', help='Web Server and Chat Engine IP Address (Default: ' + WEBSERVER_IP + ')', default=WEBSERVER_IP, type=str)
  parser.add_argument('-p','--port', action='store', help='Web Server listening port (Value: 1 to 65535; Default: ' + str(WEBSERVER_PORT) + ')', default=WEBSERVER_PORT, type=int)
  parser.add_argument('-w','--wsport', action='store', help='Chat Engine Web Socket listening port (Value: 1 to 65535; Default: ' + str(WEBSOCKET_PORT) + ')', default=WEBSOCKET_PORT, type=int)
  parser.add_argument('-n','--admin-nickname', action='store', help='Admin nickname (Value: [A-Z0-9], min 4, max 15 characters; Default: ' + ADMIN['nickname'] + ')', default=ADMIN['nickname'], type=str)
  parser.add_argument('--admin-private-key', action='store', help='Admin custom Private Key File (generate with \"openssl genrsa -out private.pem 4096\"', type=str)
  parser.add_argument('--welcome', action='store', help='Welcome message', type=str)
  parser.add_argument('--disable-all', action='store_true', help='Prevent users to send messages to @all destination (admin can always send to @all)')
  parser.add_argument('--only-admin', action='store_true', help='Allow users to send messages only to admin (forces --disable-all, admin can always send to everybody)')
  parser.add_argument('--ssl-certificate', action='store', help='Web Server SSL certificate file', type=str)
  parser.add_argument('--ssl-key', action='store', help='Web Server SSL key file', type=str)
  parser.add_argument('--ssl-cabundle', action='store', help='Web Server SSL CA Bundle file', type=str)
  parser.add_argument('--sshpfw-ip-address', action='store', help='SSH Port Forwarding IP Address', type=str)
  parser.add_argument('--sshpfw-port', action='store', help='SSH Port Forwarding Port', type=int)
  parser.add_argument('--sshpfw-user', action='store', help='SSH Port Forwarding SSH User', type=str)
  parser.add_argument('--sshpfw-keyfile', action='store', help='SSH Port Forwarding User Key File', type=str)
  parser.add_argument('-v','--version', action='version', version=PROGNAME + ' ' + VERSION)
  parser.add_argument('-a','--author', action='version', version=AUTHOR)
  args = parser.parse_args()

  try:
    # Welcome message
    print(TXT_BOLD + 'Welcome to ' + PROGNAME + ' ' + VERSION + TXT_CLEAR + '\n')
    print(TXT_BOLD + 'Instructions:' + TXT_CLEAR)
    print('[i] Send ' + TXT_BOLD + '/help' + TXT_CLEAR + ' for help')
    print('[i] Messages: ' + TXT_BOLD + '@{username} {message}' + TXT_CLEAR + '\n')

    #
    # Process args
    #

    # Web Server and Chat Engine IP Address
    try:
      socket.inet_pton(socket.AF_INET, args.ip_address)
      WEBSERVER_IP = args.ip_address
    except:
      print('[-] Invalid IP Address')
      sys.exit(1)

    # Web Server SSL Support
    WEBSERVER_SSL_CONFIG = validateWebServerSSL(args)
    if(WEBSERVER_SSL_CONFIG == False):
      print('[-] Missing Web Server SSL parameters')
      sys.exit(1);
    elif(WEBSERVER_SSL_CONFIG == True):
      try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.load_cert_chain(args.ssl_certificate, args.ssl_key)
        if args.ssl_cabundle != None:
          context.load_verify_locations(args.ssl_cabundle)
      except:
        print('[-] Invalid SSL Certificate')
        sys.exit(1)
      WEBSERVER_SSL_CONFIG = { 'cert':args.ssl_certificate, 'key':args.ssl_key, 'context':context }
      # If args.port and WEBSERVER_PORT are the same here (80), it means default port has not changed, so change port to 443
      if(args.port == WEBSERVER_PORT):
        args.port = 443

    # Web Server port
    if((args.port >= 1) and (args.port <= 65535)):
      WEBSERVER_PORT = args.port
    else:
      print('[-] Invalid Web Server port')
      sys.exit(1);

    # Chat Engine Web Socket port
    if((args.wsport >= 1) and (args.wsport <= 65535) and (args.wsport != WEBSERVER_PORT)):
      WEBSOCKET_PORT = args.wsport
    else:
      print('[-] Invalid Chat Engine Web Server port')
      sys.exit(1);

    # Admin nickname
    if(re.compile('^[A-Z0-9]{4,15}$').match(args.admin_nickname)):
      ADMIN['nickname'] = args.admin_nickname
    else:
      print('[-] Invalid Admin nickname')
      sys.exit(1);

    # Admin custom private key
    if(args.admin_private_key != None):
      ADMIN['custom-private-key'] = args.admin_private_key

    # SSH Port Forwarding configuration
    SSH_PFW_CONFIG = validateSSHPFW(args)
    if(SSH_PFW_CONFIG == False):
      print('[-] Missing SSH Port Forward parameters')
      sys.exit(1);
    elif(SSH_PFW_CONFIG == True):
      SSH_PFW_CONFIG = { 'ip':args.sshpfw_ip_address, 'port':str(args.sshpfw_port), 'user':args.sshpfw_user, 'key':args.sshpfw_keyfile }

    # Misc config: Welcome message
    if(args.welcome != None):
      MISC_CONFIG['welcome-message'] = args.welcome

    # Misc config: Disable @all destination for users
    if(args.disable_all):
      MISC_CONFIG['disable-all'] = True

    # Misc config: Allow users to send messages only to admin
    if(args.only_admin):
      MISC_CONFIG['only-admin'] = True
      MISC_CONFIG['disable-all'] = True

    #
    # Start services
    #
    asyncio.run(startServices(args))

  except:
    pass
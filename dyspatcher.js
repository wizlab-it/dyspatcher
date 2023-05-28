var CHAT = {
  // GLobal variables
  SOCKET: null,
  USER: null,
  ADMIN: null,
  OBJ_IDS: ["loading", "chat", "user", "chat-connect", "chat-localuser-name", "chat-userslist", "chat-localuser", "chat-message", "chat-message-txt", "userslist", "userslist-toggler", "chatInitButton", "receivedMessages", "custom-keys", "chat-localuser-keyid"],
  OBJS: {},
  CONFIGS: { "is-admin":false },
  CRYPTO: {
    "config": {
      "oaep": { "name":"RSA-OAEP", "modulusLength":4096, "publicExponent": new Uint8Array([1, 0, 1]), "hash":"SHA-256" },
      "pss": { "name":"RSA-PSS", "hash":"SHA-256", "saltLength":256 },
    },
    "keys": { "objs":null, "pem":{}, "keyid":null, "files":{ "private":null, "public":null } },
    "keyCache": { },
  },

  // Constants
  PEM_PRIVATE_HEADER: "-----BEGIN PRIVATE KEY-----",
  PEM_PRIVATE_FOOTER: "-----END PRIVATE KEY-----",
  PEM_PUBLIC_HEADER: "-----BEGIN PUBLIC KEY-----",
  PEM_PUBLIC_FOOTER: "-----END PUBLIC KEY-----",

  /////////////////////////////////////////////////////////

  //
  // Web Socket Chat Engine
  //

  // Application load
  load: async function() {
    // Load objects
    for(i of CHAT.OBJ_IDS) {
      CHAT.OBJS[i] = document.getElementById(i);
    }
    CHAT.OBJS["loading"].innerHTML += "<b>OK</b>!";

    // Generate encryption keys
    CHAT.OBJS["loading"].innerHTML += "<br>Generating crypto keys... ";
    if(!await CHAT.cryptoGenRSAKeys()) {
      CHAT.OBJS["loading"].innerHTML += "<span class='red'><b>Error</b>!</span>";
      CHAT.OBJS["loading"].innerHTML += "<p>Error loading crypto (unencrypted connection?)</p>";
      return;
    }
    CHAT.OBJS["loading"].innerHTML += "<b>OK</b>!";

    //Wait 1 second then allow to connect
    CHAT.OBJS["loading"].innerHTML += "<h3>Done!</h3>";
    setTimeout(function() {
      CHAT.OBJS["loading"].remove();
      CHAT.OBJS["chat-connect"].classList.add("active");
      CHAT.OBJS["user"].focus();
    }, 1000);
  },

  // Init chat engine on "Connect" button click
  chatInit: async function(port, isSSL) {
    // Check if user is ok
    if(CHAT.OBJS["user"].value.match(/^[a-z0-9]{4,15}$/) == null) {
      CHAT.printMessage("signal", "Invalid user. User must be 4-15 characters long, only lowercase letters and digits");
      CHAT.OBJS["user"].value = "";
      CHAT.OBJS["user"].focus();
      return;
    }
    CHAT.USER = CHAT.OBJS["user"].value;

    // Check if custom keys are set
    if(CHAT.CRYPTO.keys.files.private || CHAT.CRYPTO.keys.files.public) {
      if(!await CHAT.cryptoImportCustomRSAKeys(CHAT.CRYPTO.keys.files.private, CHAT.CRYPTO.keys.files.public)) {
        CHAT.printMessage("signal", "Invalid custom keys");
        return;
      }
    }

    // Open websocket and set listeners
    CHAT.SOCKET = new WebSocket("ws" + ((isSSL) ? "s" : "") + "://" + window.location.hostname + ":" + port);
    CHAT.SOCKET.addEventListener("open", CHAT.websocketEventHandlerOpen);
    CHAT.SOCKET.addEventListener("message", CHAT.websocketEventHandlerMessage);
    CHAT.SOCKET.addEventListener("error", CHAT.websocketEventHandlerError);
    CHAT.SOCKET.addEventListener("close", CHAT.websocketEventHandlerClose);
  },

  // Disconnect from chat server
  chatDisconnect: function() {
    CHAT.SOCKET.close();
    CHAT.setInterface(false);
  },

  // WebSocket even handler: "open"
  // Interface "connected" is shown when config is recevied from the server
  websocketEventHandlerOpen: function(event) {
    CHAT.sendCommand("signal", { "code":"chat-join", "publickey":CHAT.CRYPTO.keys.pem.public });
  },

  // WebSocket even handler: "close"
  websocketEventHandlerClose: function(event) {
    CHAT.printMessage("signal", "Connection closed");
    CHAT.setInterface(false);
  },

  // WebSocket even handler: "error"
  websocketEventHandlerError: function(event) {
    CHAT.printMessage("signal", "Connection failed");
    if(event.target.url.indexOf("wss://") === 0) {
      CHAT.printMessage("signal", "<b>WARNING</b><br>The connection seems to use a self-signed SSL certificate. Please <a href='" + event.target.url.replace("wss://", "https://") + "' target='_blank'>click here &#8663;</a> then accept the certificate, close the new window, and finally try again to connect.");
    }
    CHAT.setInterface(false);
  },

  // WebSocket even handler: "message"
  websocketEventHandlerMessage: function(event) {
    try {
      payload = JSON.parse(event.data)
      switch(payload.cmd) {

        // Chat message received
        case "message":
          switch(payload.data.algo) {
            case "aes":
              CHAT.cryptoAesDecryptAndPrint(payload.data);
              break;
            case "rsa":
              CHAT.cryptoRsaDecryptAndPrint(payload.data);
              break;
          }
          break;

        // Signal received
        case "signal":
          switch(payload.data.code) {

            // Generic notice message
            case "notice":
              CHAT.printMessage("signal", payload.data.notice);
              break;

            // New user joined chat
            case "chat-join":
              CHAT.printMessage("signal", payload.user + " joined chat");
              CHAT.userslistAdd(payload.user, payload.data.publickey);
              break;

            // User left chat
            case "chat-left":
              CHAT.printMessage("signal", payload.user + " abandoned chat");
              CHAT.userslistRemove(payload.user);
              break;

            // Users list
            case "chat-userslist":
              CHAT.userslistClear();
              let userslist = JSON.parse(payload.data.userslist);
              CHAT.ADMIN = userslist[0].name;
              for(user of userslist) {
                CHAT.userslistAdd(user["name"], user["publickey"]);
              }
              break;

            // Selected user is invalid
            case "chat-invaliduser":
              CHAT.printMessage("signal", "The name you selected is not available");
              CHAT.OBJS["user"].value = "";
              CHAT.OBJS["user"].focus();
              break;
          }
          break;

        // Config received
        case "config":
          // Save full configs
          CHAT.CONFIGS = payload.data;

          // Store own username, Key ID and @all AES key
          CHAT.USER = payload.data.user;
          CHAT.CRYPTO.keys.keyid = payload.data.keyid;
          try {
            window.crypto.subtle.importKey("raw", CHAT.str2ab(atob(payload.data["aeskey"])), "AES-GCM", true, ["encrypt", "decrypt"]).then(aeskey => {
              CHAT.CRYPTO.keyCache["aeskey"] = aeskey;
            })
          } catch(e) { }

          // Show connected interface
          CHAT.setInterface(true);
          break;
      }
    } catch { }
  },

  // Send generic command
  sendCommand: function(cmd, data) {
    let payload = { "cmd":cmd, "user":CHAT.USER, "data":data }
    CHAT.SOCKET.send(JSON.stringify(payload));
  },

  // Send message
  sendMessage: function(destination, message) {
    let msgPayload = { "from":CHAT.USER, "to":destination, "message":message };
    let msgPayloadStr = JSON.stringify(msgPayload);

    // If it's a message for @all, then send it AES encrypted
    if(destination == "all") {
      // If not web admin: if @all destination is disabled or no @all AES key exists, then exists immediately
      if(!CHAT.CONFIGS["is-admin"] && (CHAT.CONFIGS["disable-all"] || !CHAT.CRYPTO.keyCache["aeskey"])) {
        CHAT.printMessage("signal", "You can't send messages to @all", true);
        return;
      }

      //AES Encrypt message and send
      CHAT.printMessage("my", msgPayload);
      CHAT.cryptoAesEncryptAndSend(msgPayloadStr);
      return;

    } else {

      // If destination public key is not available, then exits
      let publickey = CHAT.cryptoGetUserRSAPublicKey(destination);
      if(!publickey || !publickey.encrypt) {
        CHAT.printMessage("signal", "Unknown destination or missing encryption key", true);
        return;
      }

      //RSA Encrypt message and send
      CHAT.printMessage("my", msgPayload);
      CHAT.cryptoRsaEncryptAndSend(publickey.encrypt, msgPayloadStr);

      // If user is admin web, then send message to server to show it in local chat
      if(CHAT.CONFIGS["is-admin"] && (destination != CHAT.ADMIN)) {
        CHAT.cryptoRsaEncryptAndSend(CHAT.CRYPTO.keys.objs.publicKey, msgPayloadStr);
      }
    }
  },


  /////////////////////////////////////////////////////////

  //
  // Crypto methods
  //

  // Load key file from filesystem
  loadKeyFile: function(e) {
    let file = e.target.files[0];
    let type = e.target.dataset.keytype;
    var reader = new FileReader();
    reader.onload = function(e) {
      let fileContent = e.target.result.trim();
      switch(type) {
        case "private":
          if(fileContent.indexOf(CHAT.PEM_PRIVATE_HEADER) !== 0) {
            alert("Invalid Private Key file");
            return;
          }
          CHAT.CRYPTO.keys.files.private = fileContent;
          break;
        case "public":
          if(fileContent.indexOf(CHAT.PEM_PUBLIC_HEADER) !== 0) {
            alert("Invalid Public Key file");
            return;
          }
          CHAT.CRYPTO.keys.files.public = fileContent;
          break;
      }
    };
    reader.readAsText(file);
  },

  // Generate Keys
  cryptoGenRSAKeys: function() {
    return new Promise((keysStatus) => {
      try {
        window.crypto.subtle.generateKey(CHAT.CRYPTO.config.oaep, true, ["encrypt", "decrypt"]).then(keyPair => {
          CHAT.CRYPTO.keys.objs = keyPair;

          // Export private key
          window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey).then(privateKey => {
            CHAT.CRYPTO.keys.pem.private = window.btoa(CHAT.ab2str(privateKey));

            // Import private key for message signature
            window.crypto.subtle.importKey("pkcs8", privateKey, CHAT.CRYPTO.config.pss, true, ["sign"]).then(signKey => {
              CHAT.CRYPTO.keys.objs.signKey = signKey;

              // Export public key
              window.crypto.subtle.exportKey("spki", keyPair.publicKey).then(publicKey => {
                CHAT.CRYPTO.keys.pem.public = window.btoa(CHAT.ab2str(publicKey));

                // End of keys generation
                keysStatus(true);
                return;
              });
            });
          });
        });
      } catch(e) {
        keysStatus(false);
        return;
      }
    });
  },

  // Import Custom Keys
  cryptoImportCustomRSAKeys: function(privateKeyPem, publicKeyPem) {
    return new Promise((keysStatus) => {
      try {
        // Convert PEM to binary
        let privateKeyBin = CHAT.str2ab(window.atob(privateKeyPem.substring(CHAT.PEM_PRIVATE_HEADER.length, (privateKeyPem.length - CHAT.PEM_PRIVATE_FOOTER.length))));
        let publicKeyBin = CHAT.str2ab(window.atob(publicKeyPem.substring(CHAT.PEM_PUBLIC_HEADER.length, (publicKeyPem.length - CHAT.PEM_PUBLIC_FOOTER.length))));

        // Load private key
        window.crypto.subtle.importKey("pkcs8", privateKeyBin, CHAT.CRYPTO.config.oaep, true, ["decrypt"]).then(privateKey => {
          CHAT.CRYPTO.keys.objs.privateKey = privateKey;

          // Load key for sign
          window.crypto.subtle.importKey("pkcs8", privateKeyBin, CHAT.CRYPTO.config.pss, true, ["sign"]).then(signKey => {
            CHAT.CRYPTO.keys.objs.signKey = signKey;

            // Export private key
            window.crypto.subtle.exportKey("pkcs8", privateKey).then(privateKey => {
              CHAT.CRYPTO.keys.pem.private = window.btoa(CHAT.ab2str(privateKey));

              // Load public key
              window.crypto.subtle.importKey("spki", publicKeyBin, CHAT.CRYPTO.config.oaep, true, ["encrypt"]).then(publicKey => {
                CHAT.CRYPTO.keys.objs.publicKey = publicKey;

                // Export public key
                window.crypto.subtle.exportKey("spki", publicKey).then(publicKey => {
                  CHAT.CRYPTO.keys.pem.public = window.btoa(CHAT.ab2str(publicKey));

                  // End of keys import
                  keysStatus(true);
                  return;
                });
              });
            });
          });
        });
      } catch(e) {
        keysStatus(false);
        return;
      }
    });
  },

  // Import public key
  cryptoImportRSAPublicKey: function(hash, publickeyB64) {
    publickey = CHAT.str2ab(window.atob(publickeyB64));
    window.crypto.subtle.importKey("spki", publickey, CHAT.CRYPTO.config.oaep, true, ["encrypt"]).then(publickeyEncrypt => {
      CHAT.CRYPTO.keyCache[hash] = { "encrypt":publickeyEncrypt };
      window.crypto.subtle.importKey("spki", publickey, CHAT.CRYPTO.config.pss, true, ["verify"]).then(publickeyVerify => {
        CHAT.CRYPTO.keyCache[hash]["verify"] = publickeyVerify;
      });
    });
  },

  // Download encryption keys
  cryptoDownloadRSAKey: function(type) {
    let pemKey = "";
    switch(type) {
      case "private":
        pemKey += CHAT.PEM_PRIVATE_HEADER + "\n";
        pemKey += CHAT.CRYPTO.keys.pem.private.replace(/([^\n]{1,64})/g, '$1\n');
        pemKey += CHAT.PEM_PRIVATE_FOOTER + "\n";
        break;
      case "public":
        pemKey += CHAT.PEM_PUBLIC_HEADER + "\n";
        pemKey += CHAT.CRYPTO.keys.pem.public.replace(/([^\n]{1,64})/g, '$1\n');
        pemKey += CHAT.PEM_PUBLIC_FOOTER + "\n";
        break;
      default:
        return;
    }
    let temp = document.createElement("a");
    let blob = new Blob([pemKey], {"type":"text/plain"});
    temp.href = window.URL.createObjectURL(blob);
    temp.download = type + ".pem";
    temp.click();
  },

  // AES: encrypt message and send
  cryptoAesEncryptAndSend: function(plaintext) {
    try {
      let iv = window.crypto.getRandomValues(new Uint8Array(16));
      let plaintextAB = CHAT.str2ab(plaintext);
      window.crypto.subtle.encrypt({ "name":"AES-GCM", "iv":iv }, CHAT.CRYPTO.keyCache["aeskey"], plaintextAB).then(ciphertext => {
        let ciphertextB64 = window.btoa(CHAT.ab2str(ciphertext));
        let ivB64 = window.btoa(CHAT.ab2str(iv));
        window.crypto.subtle.sign(CHAT.CRYPTO.config.pss, CHAT.CRYPTO.keys.objs.signKey, plaintextAB).then(signature => {
          let signatureB64 = window.btoa(CHAT.ab2str(signature));
          CHAT.sendCommand("message", { "ciphertext":ciphertextB64, "iv":ivB64, "signature":signatureB64, "algo":"aes" });
        });
      });
    } catch(e) { }
  },

  // AES: decrypt message and print
  cryptoAesDecryptAndPrint: function(payload) {
    try {
      let iv = CHAT.str2ab(atob(payload.iv));
      let ciphertext = CHAT.str2ab(atob(payload.ciphertext));
      let signature = CHAT.str2ab(atob(payload.signature));
      window.crypto.subtle.decrypt({ "name":"AES-GCM", "iv":iv }, CHAT.CRYPTO.keyCache["aeskey"], ciphertext).then(plaintext => {
        let plaintextObj = JSON.parse(CHAT.ab2str(plaintext));
        if(plaintextObj.from != CHAT.USER) {
          let publickey = CHAT.cryptoGetUserRSAPublicKey(plaintextObj.from);
          if(publickey && publickey.verify) {
            window.crypto.subtle.verify(CHAT.CRYPTO.config.pss, publickey.verify, signature, plaintext).then(() => {
              CHAT.printMessage("other", plaintextObj);
            });
          }
        }
      });
    } catch(e) { }
  },

  // Get user public key from cache
  cryptoGetUserRSAPublicKey: function(user) {
    try {
      let hash = document.getElementById("userslist-user-" + user).dataset.publickey;
      if(hash in CHAT.CRYPTO.keyCache) {
        return CHAT.CRYPTO.keyCache[hash];
      }
    } catch(e) {
      return false;
    }
    return false;
  },

  // RSA: encrypt message and send
  cryptoRsaEncryptAndSend: function(publickey, message) {
    message = CHAT.str2ab(message);
    window.crypto.subtle.encrypt({ "name":CHAT.CRYPTO.config.oaep.name }, publickey, message).then(ciphertext => {
      let ciphertextB64 = window.btoa(CHAT.ab2str(ciphertext));
      window.crypto.subtle.sign(CHAT.CRYPTO.config.pss, CHAT.CRYPTO.keys.objs.signKey, message).then(signature => {
        let signatureB64 = window.btoa(CHAT.ab2str(signature));
        CHAT.sendCommand("message", { "ciphertext":ciphertextB64, "signature":signatureB64, "algo":"rsa" });
      });
    });
  },

  // RSA: decrypt message, check signature and print
  cryptoRsaDecryptAndPrint: function(ciphertext) {
    window.crypto.subtle.decrypt({ "name":CHAT.CRYPTO.config.oaep.name }, CHAT.CRYPTO.keys.objs.privateKey, CHAT.str2ab(window.atob(ciphertext.ciphertext))).then(plaintextAB => {
      let plaintext = CHAT.ab2str(plaintextAB);
      let plaintextObj = JSON.parse(plaintext);
      let publickey = CHAT.cryptoGetUserRSAPublicKey(plaintextObj.from);
      if(publickey && publickey.verify) {
        window.crypto.subtle.verify(CHAT.CRYPTO.config.pss, publickey.verify, CHAT.str2ab(ciphertext.signature), CHAT.str2ab(plaintext)).then(() => {
          CHAT.printMessage("other", plaintextObj);
        });
      }
    }).catch(e => { });
  },


  /////////////////////////////////////////////////////////

  //
  // Support methods
  //

  // Convert array buffer to string
  ab2str: function(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  },

  // Convert string to array buffer
  str2ab: function(str) {
    let byteArray = new Uint8Array(str.length);
    for(let i=0; i<str.length; i++) {
      byteArray[i] = str.codePointAt(i);
    }
    return byteArray;
  },


  /////////////////////////////////////////////////////////

  //
  // Chat Interface methods
  //

  setInterface: function(isConnected) {
    if(isConnected) {
      CHAT.OBJS["chat-connect"].classList.remove("active");
      CHAT.OBJS["chat-localuser-name"].innerHTML = CHAT.USER;
      CHAT.OBJS["chat-localuser-keyid"].innerHTML = CHAT.CRYPTO.keys.keyid.substr(0, 12);
      CHAT.OBJS["chat-localuser-keyid"].title = "Full Key ID: " + CHAT.CRYPTO.keys.keyid;
      CHAT.OBJS["chat-userslist"].classList.add("active");
      CHAT.OBJS["chat-localuser"].style.display = "block";
      CHAT.OBJS["chat-message"].style.display = "flex";
      CHAT.OBJS["userslist-toggler"].classList.add("active");
      CHAT.OBJS["chat-message-txt"].focus();
    } else {
      CHAT.OBJS["chat-localuser"].style.display = "none";
      CHAT.OBJS["chat-localuser-name"].innerHTML = "";
      CHAT.OBJS["chat-connect"].classList.add("active");
      CHAT.OBJS["chat-message"].style.display = "none";
      CHAT.OBJS["chat-userslist"].classList.remove("active");
      CHAT.OBJS["userslist-toggler"].classList.remove("active");
      CHAT.userslistClear();
    }
  },

  // Username field event handler
  userEventHandlerKeypress: function(event) {
    if(event.key === "Enter") {
      event.preventDefault();
      CHAT.OBJS["chatInitButton"].click();
    }
  },

  // Message input keypress handler
  messageEventHandlerKeypress: function(event) {
    if(event.key === "Enter") {
      event.preventDefault();
      CHAT.sendMessageEventHandlerClick();
    }
  },

  // Send message button click handler
  sendMessageEventHandlerClick: function() {
    CHAT.OBJS["chat-message-txt"].value = CHAT.OBJS["chat-message-txt"].value.trim();
    if(CHAT.OBJS["chat-message-txt"].value == "") return;

    // Parse message and send it if it's ok
    message = (/@([a-zA-Z0-9]*) (.*)/g).exec(CHAT.OBJS["chat-message-txt"].value.trim());
    if((message == null) || (message[1] == "") || (message[2] == "")) {
      CHAT.printMessage("signal", "Destination or message missing");
      return false;
    }
    CHAT.sendMessage(message[1].trim(), message[2].trim());

    CHAT.OBJS["chat-message-txt"].value = (CHAT.OBJS["chat-message-txt"].value.charAt(0) == "@") ? CHAT.OBJS["chat-message-txt"].value.substring(0, CHAT.OBJS["chat-message-txt"].value.indexOf(" ")) + " " : "";
    CHAT.OBJS["chat-message-txt"].focus();
  },

  // Userlist toggles button click handler
  userslistTogglerEventHandlerClick: function(event) {
    CHAT.OBJS["userslist-toggler"].innerHTML = (CHAT.OBJS["chat"].classList.toggle("userslist-open")) ? "▲ Users list ▲" : "▼ Users list ▼";
  },

  // Set message destination (@username in message field)
  setMessageDestination: function(user) {
    user = user.trim();
    if(user == "") return false;
    CHAT.OBJS["chat-message-txt"].value = "@" + user + " ";
    CHAT.OBJS["chat-message-txt"].focus();
  },

  // Print received message
  printMessage: function(type, message, clearMessageTxtInputField=false) {
    // Check first if the message is the local copy of an admin message sent from the server, and if yes mangle the message accordingly
    if(CHAT.CONFIGS["is-admin"]) {
      if(message.isWebAdminMsgCopy) {
        message.message = JSON.parse(message.message);
        if(message.message.to == CHAT.ADMIN) return;
        message = { "from":message.from, "to":message.message.to + " (via server)", "message":message.message.message };
        type = "my";
      } else {
        if((message.from == CHAT.ADMIN) && (message.to != CHAT.ADMIN) && (type == "other")) return;
      }
    }

    // Message block
    let msgBlock = document.createElement("li");
    msgBlock.className = "clearfix";

    // Message user
    if((type != "signal")) {
      let msgUser = document.createElement("div");
      msgUser.classList.add("message-user");
      switch(type) {
        case "my":
          msgUser.innerHTML = "To <b>" + message.to + "</b>:";
          msgUser.classList.add("text-right");
          msgUser.addEventListener("click", function() { CHAT.setMessageDestination(message.to); });
          break;
        case "other":
          msgUser.innerHTML = "From <b>" + message.from + "</b> to <b>" + message.to + "</b>:";
          msgUser.addEventListener("click", function() { CHAT.setMessageDestination(message.from); });
          break;
      }
      msgBlock.appendChild(msgUser);
    }

    // Message text
    let msgMessage = document.createElement("div");
    msgMessage.classList.add("message");
    msgMessage.classList.add(type);
    if((type == "signal")) {
      msgMessage.innerHTML = message + "<div class='message-date'>" + (new Date()).toLocaleString() + "</div>";
    } else {
      if((message.from == CHAT.ADMIN) && (message.to == CHAT.ADMIN)) msgMessage.classList.add("admin2admin");
      else if((message.from == CHAT.ADMIN) || (message.to == CHAT.ADMIN)) msgMessage.classList.add("admin");

      // Message content
      msgMessage.appendChild(document.createTextNode(message.message));

      // Date
      let msgDate = document.createElement("div");
      msgDate.classList.add("message-date");
      msgDate.appendChild(document.createTextNode((new Date()).toLocaleString()));
      msgMessage.appendChild(msgDate);

      msgMessage.addEventListener("click", function() { CHAT.setMessageDestination((type == "my") ? message.to : message.from); });
    }
    msgBlock.appendChild(msgMessage);

    //Output new message
    CHAT.OBJS["receivedMessages"].appendChild(msgBlock);
    CHAT.OBJS["receivedMessages"].scrollTop = CHAT.OBJS["receivedMessages"].scrollHeight;

    //Check if to clear the new message text input field
    if(clearMessageTxtInputField) {
      CHAT.OBJS["chat-message-txt"].value = "";
      CHAT.OBJS["chat-message-txt"].focus();
    }
  },

  // Add user to list
  userslistAdd: function(user, publickey) {
    let userBlock = document.createElement("li");
    userBlock.id = "userslist-user-" + user;
    userBlock.title = "Full Key ID: " + publickey.hash;
    userBlock.classList.add("userslist-user");
    if((user == CHAT.USER) && (user != CHAT.ADMIN)) userBlock.classList.add("hide");
    userBlock.innerHTML = "<div class='user'>" + user + "</div><div class='keyid'>Key ID: " + publickey.hash.substr(0, 12) + "</div>";
    userBlock.dataset.user = user;
    if(((typeof publickey) === "object") && (publickey.text != "")) {
      userBlock.dataset.user = user;
      userBlock.dataset.publickey = publickey.hash;
      CHAT.cryptoImportRSAPublicKey(publickey.hash, publickey.text);
      userBlock.classList.add("lock");
    }
    userBlock.addEventListener("click", function(event) {
      CHAT.setMessageDestination(event.target.dataset.user);
    });
    CHAT.OBJS["userslist"].appendChild(userBlock);
  },

  // Remove user from list
  userslistRemove: function(user) {
    let userBlock = document.getElementById("userslist-user-" + user);
    if(userBlock) {
      CHAT.OBJS["userslist"].removeChild(userBlock);
    }
  },

  // Clear users list
  userslistClear: function() {
    // Remove all destination
    while(CHAT.OBJS["userslist"].firstChild) {
      CHAT.OBJS["userslist"].removeChild(userslist.firstChild);
    }

    // Add @all destination
    if(!CHAT.CONFIGS["disable-all"] || CHAT.CONFIGS["is-admin"]) {
      let userBlock = document.createElement("li");
      userBlock.innerHTML = "<div class='user'>@all</div>";
      userBlock.classList.add("lock");
      userBlock.addEventListener("click", function(event) {
        CHAT.setMessageDestination("all");
      });
      CHAT.OBJS["userslist"].appendChild(userBlock);
    }
  },

  showCustomKeysFields: function(event) {
    event.target.innerHTML = (CHAT.OBJS["custom-keys"].classList.toggle("active")) ? "Use random keys" : "Use custom keys";
  }
}


// Load chat application when page loading is complete
window.addEventListener("load", CHAT.load);
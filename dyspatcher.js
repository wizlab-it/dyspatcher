var CHAT = {
  // GLobal variables
  SOCKET: null,
  USER: null,
  ADMIN: null,
  OBJ_IDS: ["loading", "chat", "user", "chat-connect", "chat-localuser-name", "chat-userslist", "chat-localuser", "chat-message", "chat-message-txt", "userslist", "userslist-toggler", "chatInitButton", "receivedMessages"],
  OBJS: {},
  CONFIGS: null,
  CRYPTO: {
    "config": { "name":"RSA-OAEP", "modulusLength":4096, "publicExponent": new Uint8Array([1, 0, 1]), "hash":"SHA-256" },
    "sign": { "name":"RSA-PSS", "hash":"SHA-256", "saltLength":256 },
    "keys": { "raw":null, "private":null, "privateSign":null, "public":null },
    "publickeyCache": {},
  },

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
    if(!await CHAT.cryptoGenKeys()) {
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
  chatInit: function(port, isSSL) {
    // Check if user is ok
    if(CHAT.OBJS["user"].value.match(/^[a-z0-9]{4,15}$/) == null) {
      CHAT.printMessage("signal", "Invalid user. User must be 4-15 characters long, only lowercase letters and digits");
      CHAT.OBJS["user"].value = "";
      CHAT.OBJS["user"].focus();
      return;
    }
    CHAT.USER = CHAT.OBJS["user"].value;

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
  websocketEventHandlerOpen: function(event) {
    CHAT.sendCommand("signal", { "code":"chat-join", "publickey":CHAT.CRYPTO.keys.public });
    CHAT.setInterface(true);
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
          CHAT.messageDecryptAndPrint(payload.data);
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
          CHAT.CONFIGS = payload.data;
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
  sendMessage: function(destination, message, isAll=false) {
    // If it's a message for @all, then generates one message for each destination and exists
    if(destination == "all") {
      if(CHAT.CONFIGS["disable-all"]) {
        CHAT.printMessage("signal", "You can't send messages to @all", true);
        return;
      }
      let destinations = document.querySelectorAll(".userslist-user");
      CHAT.printMessage("my", { "from":CHAT.USER, "to":"@all", "message":message });
      for(user of destinations) {
        CHAT.sendMessage(user.dataset.user, message, true);
      }
      return;
    }

    // If destination public key is available, then encrypt the message and send it and print the send message in local chat
    let publickey = CHAT.getUserPublicKey(destination);
    if(publickey && publickey["encrypt"]) {
      let msgPayload = { "from":CHAT.USER, "to":((isAll) ? "@all" : destination), "message":message };
      if(!isAll) CHAT.printMessage("my", msgPayload);
      CHAT.messageEncryptAndSend(publickey["encrypt"], JSON.stringify(msgPayload));
    } else {
      CHAT.printMessage("signal", "Unknown destination or missing encryption key", true);
    }
  },


  /////////////////////////////////////////////////////////

  //
  // Crypto methods
  //

  // Generate Keys
  cryptoGenKeys: function() {
    return new Promise((keysStatus) => {
      try {
        window.crypto.subtle.generateKey(CHAT.CRYPTO.config, true, ["encrypt", "decrypt"]).then(keyPair => {
          CHAT.CRYPTO.keys.raw = keyPair;

          // Export private key
          window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey).then(privateKey => {
            CHAT.CRYPTO.keys.private = window.btoa(CHAT.ab2str(privateKey));

            // Import private key for message signature
            window.crypto.subtle.importKey("pkcs8", privateKey, CHAT.CRYPTO.sign, true, ["sign"]).then(privateSign => {
              CHAT.CRYPTO.keys.privateSign = privateSign;

              // Export public key
              window.crypto.subtle.exportKey("spki", keyPair.publicKey).then(publicKey => {
                CHAT.CRYPTO.keys.public = window.btoa(CHAT.ab2str(publicKey));
              });

              keysStatus(true);
              return;
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
  cryptoImportPublicKey: function(hash, publickeyB64) {
    publickeyRaw = CHAT.str2ab(window.atob(publickeyB64));
    window.crypto.subtle.importKey("spki", publickeyRaw, CHAT.CRYPTO.config, true, ["encrypt"]).then(publickeyEncrypt => {
      CHAT.CRYPTO.publickeyCache[hash] = { "encrypt":publickeyEncrypt };
      window.crypto.subtle.importKey("spki", publickeyRaw, CHAT.CRYPTO.sign, true, ["verify"]).then(publickeyVerify => {
        CHAT.CRYPTO.publickeyCache[hash]["verify"] = publickeyVerify;
      });
    });
  },

  // Get user public key from cache
  getUserPublicKey: function(user) {
    try {
      let hash = document.getElementById("userslist-user-" + user).dataset.publickey;
      if(hash in CHAT.CRYPTO.publickeyCache) {
        return CHAT.CRYPTO.publickeyCache[hash];
      }
    } catch(e) {
      return false;
    }
    return false;
  },

  //Encrypt a message
  messageEncryptAndSend: function(publickey, message) {
    message = CHAT.str2ab(message);
    window.crypto.subtle.encrypt({ "name":CHAT.CRYPTO.config.name }, publickey, message).then(messageEncrypted => {
      let messageEncryptedB64 = window.btoa(CHAT.ab2str(messageEncrypted));
      window.crypto.subtle.sign(CHAT.CRYPTO.sign, CHAT.CRYPTO.keys.privateSign, message).then(signature => {
        let signatureB64 = window.btoa(CHAT.ab2str(signature));
        CHAT.sendCommand("message", { "message":messageEncryptedB64, "signature":signatureB64 });
      });
    });
  },

  //Decrypt message and check signature
  messageDecryptAndPrint: function(message) {
    window.crypto.subtle.decrypt({ "name":CHAT.CRYPTO.config.name }, CHAT.CRYPTO.keys.raw.privateKey, CHAT.str2ab(window.atob(message.message))).then(messagePlainAB => {
      let messageStr = CHAT.ab2str(messagePlainAB);
      let messageObj = JSON.parse(messageStr);
      let publickey = CHAT.getUserPublicKey(messageObj.from);
      if(publickey && publickey.verify) {
        window.crypto.subtle.verify(CHAT.CRYPTO.sign, publickey.verify, CHAT.str2ab(message.signature), CHAT.str2ab(messageStr)).then(() => {
          CHAT.printMessage("other", messageObj);
        });
      }
    }).catch(e => {});
  },

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
    CHAT.OBJS["userslist-toggler"].innerHTML = (CHAT.OBJS["chat"].classList.toggle('userslist-open')) ? "▲ Users list ▲" : "▼ Users list ▼";
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
    // Message block
    let msgBlock = document.createElement("li");
    msgBlock.className = "clearfix";

    // Message user block
    if((type != "signal")) {
      let msgUserBlock = document.createElement("div");
      msgUserBlock.classList.add("message-user");
      switch(type) {
        case "my":
          msgUserBlock.innerHTML = "To <b>" + message.to + "</b>:";
          msgUserBlock.classList.add("text-right");
          msgUserBlock.addEventListener("click", function() { CHAT.setMessageDestination(message.to); });
          break;
        case "other":
          msgUserBlock.innerHTML = "From <b>" + message.from + "</b> to <b>" + message.to + "</b>:";
          msgUserBlock.addEventListener("click", function() { CHAT.setMessageDestination(message.from); });
      }
      msgBlock.appendChild(msgUserBlock);
    }

    // Message text
    let msgMessage = document.createElement("div");
    msgMessage.classList.add("message");
    msgMessage.classList.add(type);
    if(typeof message === "object") {
      if((message.from == CHAT.ADMIN) || (message.to == CHAT.ADMIN)) msgMessage.classList.add("admin");

      // If it's a signal then print as HTML, if message add as text node
      if((type == "signal")) {
        msgMessage.innerHTML = message.message;
      } else {
        msgMessage.appendChild(document.createTextNode(message.message));
      }

      msgMessage.addEventListener("click", function() { CHAT.setMessageDestination((type == "my") ? message.to : message.from); });
    } else {
      msgMessage.innerHTML = message;
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
    if(user == CHAT.USER) return;
    let userBlock = document.createElement("li");
    userBlock.id = "userslist-user-" + user;
    userBlock.classList.add("userslist-user");
    userBlock.appendChild(document.createTextNode(user));
    userBlock.dataset.user = user;
    if(((typeof publickey) === "object") && (publickey.text != "")) {
      userBlock.dataset.user = user;
      userBlock.dataset.publickey = publickey.hash;
      CHAT.cryptoImportPublicKey(publickey.hash, publickey.text);
      userBlock.classList.add("lock");
    }
    userBlock.addEventListener("click", function(event) {
      CHAT.setMessageDestination(event.srcElement.dataset.user);
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
    while(CHAT.OBJS["userslist"].firstChild) {
      CHAT.OBJS["userslist"].removeChild(userslist.firstChild);
    }
  }
}


// Load chat application when page loading is complete
window.addEventListener("load", CHAT.load);
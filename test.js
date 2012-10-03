var gpg = require('./gpgme');
var fs  = require('fs');


// Test verification
if (fs.existsSync('msg.json')){
  var msg = JSON.parse(fs.readFileSync('./msg.json', 'utf8'));

  var verify = function(msg){
    if(gpg.verify(msg.signature,msg.content))
      console.log("verification success");
    else
      console.log("verification failure"); };

  verify(msg);                    // should print success
  msg.content = "bar";            // change signed content
  verify(msg);                    // should print failure
}


// Test decryption
if (fs.existsSync('cipher.txt')){
  var cipher = fs.readFileSync('cipher.txt', 'utf8');

  var decrypted = gpg.decrypt(cipher);

  console.log('decrypted content is "'+decrypted+'"');
}


// Test decryption and verification
if (fs.existsSync('signed-cipher.txt')){
  var signed_cipher = fs.readFileSync('signed-cipher.txt', 'utf8');

  var decrypted_and_verified = gpg.decryptAndVerify(signed_cipher);

  console.log('decrypted and verified content is "'+decrypted_and_verified+'"');
}


// Test signing
if (fs.existsSync('sign.json')){
  var sign = JSON.parse(fs.readFileSync('sign.json', 'utf8'));

  var signature = gpg.sign(sign.signatory, sign.content);

  console.log('content "'+sign.content+
              '" signed by "'+sign.signatory+
              '" yields signature "'+signature+'"');
}


// Test encryption
if (fs.existsSync('encrypt.json')){
  // TODO: fix weird bug, if gpg.encrypt is called before *any* text is
  //       written to STDOUT it fails.
  var encrypt = JSON.parse(fs.readFileSync('encrypt.json', 'utf8'));

  var cipher = gpg.encrypt(encrypt.recipients, encrypt.content);

  console.log('cipher text is "'+cipher+'"');
}

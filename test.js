var gpg = require('./build/Release/gpg');
var fs  = require('fs');


// Test verification
var msg = JSON.parse(fs.readFileSync('./msg.json', 'utf8'));

var verify = function(msg){
  if(gpg.verify(msg.signature,msg.content))
    console.log("verification success");
  else
    console.log("verification failure"); };

verify(msg);                    // should print success
msg.content = "bar";            // change signed content
verify(msg);                    // should print failure


// Test decryption
var cipher = fs.readFileSync('cipher.txt', 'utf8');

var decrypted = gpg.decrypt(cipher);

console.log('decrypted content is "'+decrypted+'"');


// Test decryption and verification
var signed_cipher = fs.readFileSync('signed-cipher.txt', 'utf8');

var decrypted_and_verified = gpg.decryptAndVerify(signed_cipher);

console.log('decrypted and verified content is "'+decrypted_and_verified+'"');

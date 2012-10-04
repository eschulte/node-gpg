node-gpg
========

[GNU Privacy Guard](www.gnuph.org) (GPG) bindings for node.js
supporting public key cryptography, encryption, decryption, signing
and verification.  This is based off of the
[GnuPG Made Easy](www.gnupg.org/gpgme.htlm) (GPGME) GPG C library, see
its very good documentation for more information.

License
-------

GNU GENERAL PUBLIC LICENSE v3, see the COPYING file in this directory.

Installation
------------

```sh
npm install gpgme
```

Usage
-----

* Also see the test.js file in this directory for example usage.
* Currently uses JavaScript strings for all data input and output.
* Uses ASCII Armor for all encrypted output.

Require gpg and initialize a new context.

```js
var gpg = require('gpgme');
```

### Verify
To verify a message with a signature.  First generate the signature
which can be done with the following in the shell (the `-a` indicates
ASCII armor output).

```sh
sig=$(echo foo|gpg --detach-sign -a|sed ':a;N;$!ba;s/\n/\\\\n/g')
echo "{\"content\":\"foo\\\\n\", \"signature\":\"$sig\"}" |tee msg.json
```

Then load your message and signature to a JavaScript Object, and run
the following (or run `node test.js`).

```js
var msg = JSON.parse(fs.readFileSync('./msg.json', 'utf8'));
if(gpg.verify(msg.signature,msg.content))
  console.log("verification success");
else
  console.log("verification failure");
```

### Decrypt
To decrypt an encrypted message.  First generated encrypted content by
running the following in a shell.

```sh
echo "secret contents"|gpg -e -r "Your GPG Name" -a|tee cipher.txt
```

Then run the following (or run `node test.js`).

```js
var cipher = fs.readFileSync('cipher.txt', 'utf8');
var decrypted = gpg.decrypt(cipher);
console.log('decrypted content is "'+decrypted+'"');
```

To decrypt and verify a message.  First generated encrypted content by
running the following in a shell.

```sh
echo "secret signed contents"|gpg -s -e -r "Your GPG Name" -a \
  |tee signed-cipher.txt
```
    
Then run the following (or run `node test.js`).

```js
var signed_cipher = fs.readFileSync('signed-cipher.txt', 'utf8');
var decrypted_and_verified = gpg.decryptAndVerify(signed_cipher);
console.log('decrypted and verified content is "'+decrypted_and_verified+'"');
```

### Sign
To sign a message.  First write a JSON hash holding the data to
encrypt and the name of the signatory (this name will be used by GPG
to lookup the key).

```sh
echo '{"signatory":"Your Name", "content":"foo\n"}' > sign.json
```

Then run the following (or run `node test.js`).

```js
var sign = JSON.parse(fs.readFileSync('./sign.json', 'utf8'));
var signature = gpg.sign(sign.signatory, sign.content);
console.log('content "'+sign.content+
            '" signed by "'+sign.signatory+
            '" yields signature "'+signature+'"');
```

### Encrypt
To encrypt a message.  First write a JSON hash holding a list of the
recipients and the message to encrypt.

```sh
echo '{"recipients":["Your Name"], "content":"foo\n"}' > encrypt.json
```

Then run the following (or run `node test.js`).

```js
var encrypt = JSON.parse(fs.readFileSync('encrypt.json', 'utf8'));
var cipher = gpg.encrypt(encrypt.recipients, encrypt.content);
console.log('cipher text is "'+cipher+'"');
```

TODO
----
* add a context class to allow multiple simultaneous operations
* add a key class to allow key management to take place on the JS side
  of things
* add support for asynchronous operations w/callbacks (gpgme should
  make this straightforward)

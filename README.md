node-gpg
========

Still incomplete...

[GNU Privacy Guard](www.gnuph.org) (GPG) bindings for node.js
supporting public key cryptography, encryption, decryption, signing
and verification.  This is based off of the
[GnuPG Made Easy](www.gnupg.org/gpgme.htlm) (GPGME) GPG C library, see
its very good documentation for more information.

Installation
------------

Projected (not yet submitted).

    npm install gpg

Usage
-----

* Projected (still in progress).
* Also see the test.js file in this directory for example usage.
* Currently uses JavaScript strings for all data input and output.
  I've been testing using ASCII armor GPG output.

Require gpg and initialize a new context.

    var gpg = require('gpg');

To verify a message with a signature.  First generate the signature
which can be done with the following in the shell (the `-a` indicates
ASCII armor output).

    sig=$(echo foo|gpg --detach-sign -a|sed ':a;N;$!ba;s/\n/\\\\n/g')
    echo "{\"content\":\"foo\\n\", \"signature\":\"$sig\"}" |tee msg.json

Then save your signature to a JavaScript string, and run the
following (or run `node test.js`).

    var msg = JSON.parse(fs.readFileSync('./msg.json', 'utf8'));

    if(gpg.verify(msg.signature,msg.content))
      console.log("verification success");
    else
      console.log("verification failure");

To decrypt an encrypted message.  First generated encrypted content by
running the following in a shell

    echo "secret contents"|gpg -e -r "Your GPG Name" -a|tee cipher.txt

Then run the following (or run `node test.js`).

    var cipher = fs.readFileSync('cipher.txt', 'utf8');
    var decrypted = gpg.decrypt(cipher);
    console.log('decrypted content is:'+decrypted);

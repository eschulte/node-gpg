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

Projected (still in progress).

Also see the test.js file in this directory for example usage.

Require gpg and initialize a new context.

    var gpg = require('gpg');

Verify a message with a signature.

    var msg = {
      "signature":"-----BEGIN PGP SIGNATURE-----...",
      "data":"Lorem ipsum dolor sit amet, ..."};

    if (gpg.verify(signature, content))
      console.log('signature is valid');
    else
      console.log('signature is in-valid');

Decrypt an encrypted message.

    var data = gpg.decrypt('cipher text...');

    console.log('encrypted data:'+data);

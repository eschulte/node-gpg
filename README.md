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

Require gpg and initialize a new context.

    var gpg = require('gpg');
    var context = gpg.Context();

Verify a message with a signature.

    var signature = '-----BEGIN PGP SIGNATURE---\n...';
    var content = 'Lorem ipsum dolor sit amet, ...';
    if (context.verify(signature, content))
      console.log('signature is valid');
    else
      console.log('signature is in-valid');

Decrypt an encrypted message.

    var fs = require('fs');
    
    var data = context.decrypt('./data.gpg');

    console.log('encrypted data:'+data);

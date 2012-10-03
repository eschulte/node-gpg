var binding = require('./build/Release/gpg');

exports.verify           = function(signature, content){  return binding.verify(signature, content); };
exports.decrypt          = function(cipher){              return binding.decrypt(cipher); };
exports.decryptAndVerify = function(signed_cipher){       return binding.decryptAndVerify(signed_cipher); };
exports.sign             = function(signatory, content){  return binding.sign(signatory, content); };
exports.encrypt          = function(recipients, content){ return binding.encrypt(recipients, content); };

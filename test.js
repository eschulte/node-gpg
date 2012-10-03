var gpg = require('./build/Release/gpg');

console.log('verifying');

var verrified = gpg.verify('', '');

if(verrified){
  console.log("success");
} else {
  console.log("failed");
}
